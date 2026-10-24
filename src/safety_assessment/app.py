import asyncio
import json
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .auth import COOKIE, admin_user, check_password, current_user, password_hash, session_user, token_hash
from .api.routers.llm import router as llm_router
from .api.routers.submissions import router as submissions_router
from .api.routers.imports import router as imports_router
from .application.analysis import AnalysisService
from .llm_settings import load_llm_settings
from .db import Database, now
from .environment import checked_local_path, checked_repository
from .infrastructure.llm import LLMClient
from .application.scheduling import AsyncRunner, EventBus


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9_\-.]+$")
    password: str = Field(min_length=8, max_length=128)


class UserCreate(Credentials):
    role: Literal["admin", "user"] = "user"


class ProjectCreate(BaseModel):
    project_name: str = Field(min_length=1, max_length=160)
    source_type: Literal["local", "git", "inline"] = "local"
    source_path: str = Field(default="", max_length=2048)
    task_content: str = Field(default="", max_length=10000)
    environment_type: Literal["static", "docker"] = "static"


class Settings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    default_timeout: int = Field(300, ge=5, le=3600)
    max_concurrency: int = Field(2, ge=1, le=16)
    retention_days: int = Field(30, ge=1, le=3650)
    docker_image: str = Field("python:3.12-alpine", min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_./:@-]*$")
    allow_git: bool = True
    max_files: int = Field(2000, ge=1, le=20000)
    max_file_bytes: int = Field(1048576, ge=1024, le=4194304)


def create_app(data_root: Path | None = None) -> FastAPI:
    load_dotenv(override=False)
    init_lock = threading.Lock()
    attempts = {}
    attempts_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(application):
        application.state.db = Database(data_root)
        application.state.bus = EventBus()
        application.state.runner = AsyncRunner(application.state.db, application.state.bus)
        llm_settings = load_llm_settings(application.state.db)
        application.state.analysis_service = AnalysisService(application.state.db, LLMClient(llm_settings) if llm_settings.enabled else None)
        application.state.runner.analysis_service = application.state.analysis_service
        yield
        application.state.runner.shutdown()

    application = FastAPI(title="自动化安全评估系统", version="0.1.0", lifespan=lifespan)
    application.include_router(llm_router)
    application.include_router(submissions_router)
    application.include_router(imports_router)

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method not in ("GET", "HEAD", "OPTIONS") and origin and urlsplit(origin).netloc != request.headers.get("host"):
            return Response("Cross-origin write blocked", status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if request.url.path != "/docs":
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def db(request: Request):
        return request.app.state.db

    def project_for(request: Request, project_id: int, user: dict):
        project = request.app.state.db.one("SELECT * FROM projects WHERE id=?", (project_id,))
        if not project:
            raise HTTPException(404, "项目不存在")
        if user["role"] != "admin" and project["created_by"] != user["id"]:
            raise HTTPException(403, "无权访问该项目")
        return project

    @application.get("/api/system/status")
    def system_status(database=Depends(db)):
        return {"initialized": bool(database.one("SELECT id FROM users LIMIT 1")), "database": database.backend}

    @application.post("/api/system/init", status_code=201)
    def initialize(body: Credentials, request: Request, database=Depends(db)):
        if request.client.host not in ("127.0.0.1", "::1", "testclient"):
            raise HTTPException(403, "仅允许从本机初始化管理员")
        with init_lock:
            if database.one("SELECT id FROM users LIMIT 1"):
                raise HTTPException(409, "系统已初始化")
            user_id = database.insert("users", username=body.username, password_hash=password_hash(body.password), role="admin", created_at=now())
            database.audit(user_id, "system_init", "初始化管理员")
        return {"id": user_id, "username": body.username, "role": "admin"}

    @application.post("/api/system/login")
    def login(body: Credentials, request: Request, response: Response, database=Depends(db)):
        key = request.client.host
        with attempts_lock:
            recent = [stamp for stamp in attempts.get(key, []) if stamp > time.monotonic() - 60]
            if len(recent) >= 10:
                raise HTTPException(429, "登录尝试过多，请一分钟后重试")
            recent.append(time.monotonic())
            attempts[key] = recent
        user = database.one("SELECT * FROM users WHERE username=? AND status='active'", (body.username,))
        if not user or not check_password(body.password, user["password_hash"]):
            raise HTTPException(401, "用户名或密码错误")
        token = secrets.token_urlsafe(40)
        database.execute("DELETE FROM sessions WHERE expires_at<=?", (time.time(),))
        database.insert("sessions", token_hash=token_hash(token), user_id=user["id"], expires_at=time.time() + 28800)
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=request.url.scheme == "https", max_age=28800)
        database.audit(user["id"], "login", "用户登录")
        return {"id": user["id"], "username": user["username"], "role": user["role"]}

    @application.post("/api/system/logout")
    def logout(request: Request, response: Response, database=Depends(db), user=Depends(current_user)):
        database.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(request.cookies[COOKIE]),))
        response.delete_cookie(COOKIE)
        return {"ok": True}

    @application.get("/api/system/me")
    def me(user=Depends(current_user)):
        return user

    @application.post("/api/system/users", status_code=201)
    def add_user(body: UserCreate, database=Depends(db), user=Depends(admin_user)):
        if database.one("SELECT id FROM users WHERE username=?", (body.username,)):
            raise HTTPException(409, "用户名已存在")
        user_id = database.insert("users", username=body.username, password_hash=password_hash(body.password), role=body.role, created_at=now())
        database.audit(user["id"], "user_create", f"创建用户 #{user_id}")
        return {"id": user_id, "username": body.username, "role": body.role}

    @application.get("/api/system/config")
    def get_config(database=Depends(db), user=Depends(admin_user)):
        return {key: value for key, value in database.config().items() if key != "llm_api_key"}

    @application.put("/api/system/config")
    def put_config(body: Settings, database=Depends(db), user=Depends(admin_user)):
        with database.connect() as connection:
            for key, value in body.model_dump().items():
                connection.execute("UPDATE system_config SET value=? WHERE `key`=?", (json.dumps(value), key))
        database.audit(user["id"], "config_update", "更新运行配置")
        return {key: value for key, value in database.config().items() if key != "llm_api_key"}

    @application.get("/api/system/logs")
    def audit_logs(database=Depends(db), user=Depends(admin_user)):
        return database.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200")

    @application.get("/api/examples")
    def examples(user=Depends(current_user)):
        root = Path(__file__).with_name("examples")
        return [
            {"name": "危险示例 · SQL 与 Shell 注入", "path": str(root / "unsafe"), "expected_findings": 2, "signal": True},
            {"name": "安全示例 · 参数化与无 Shell 调用", "path": str(root / "safe"), "expected_findings": 0, "signal": False},
        ]

    @application.post("/api/projects", status_code=201)
    def create_project(body: ProjectCreate, database=Depends(db), user=Depends(current_user)):
        try:
            path = body.source_path
            if body.source_type == "inline":
                path = "submitted://pending"
            elif body.source_type == "local":
                path = str(checked_local_path(path, database.root))
            else:
                if not database.config()["allow_git"]:
                    raise ValueError("仓库接入已关闭")
                path = checked_repository(path)
        except (ValueError, OSError) as error:
            raise HTTPException(422, str(error)) from error
        values = body.model_dump()
        values["source_path"] = path
        project_id = database.insert("projects", **values, environment_id="safety-" + secrets.token_hex(12), created_by=user["id"], created_at=now(), updated_at=now())
        database.audit(user["id"], "project_create", f"创建项目 #{project_id}")
        return database.one("SELECT * FROM projects WHERE id=?", (project_id,))

    @application.get("/api/projects")
    def list_projects(database=Depends(db), user=Depends(current_user)):
        sql = "SELECT * FROM projects"
        params = ()
        if user["role"] != "admin":
            sql += " WHERE created_by=?"
            params = (user["id"],)
        return database.all(sql + " ORDER BY id DESC", params)

    @application.get("/api/projects/{project_id}")
    def detail(project_id: int, request: Request, database=Depends(db), user=Depends(current_user)):
        project = project_for(request, project_id, user)
        for name, table in (("vulnerability_count", "vulnerabilities"), ("attack_path_count", "attack_paths"), ("report_count", "reports")):
            project[name] = database.one(f"SELECT COUNT(*) AS total FROM {table} WHERE project_id=?", (project_id,))["total"]
        return project

    @application.post("/api/projects/{project_id}/start")
    async def start(project_id: int, request: Request, database=Depends(db), user=Depends(current_user)):
        project_for(request, project_id, user)
        try:
            await request.app.state.runner.astart(project_id)
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
        database.audit(user["id"], "project_start", f"启动项目 #{project_id}")
        return {"project_id": project_id, "project_status": "running"}

    @application.post("/api/projects/{project_id}/stop")
    async def stop(project_id: int, request: Request, database=Depends(db), user=Depends(current_user)):
        project_for(request, project_id, user)
        try:
            await request.app.state.runner.astop(project_id)
        except (ValueError, TimeoutError) as error:
            raise HTTPException(409, str(error)) from error
        database.audit(user["id"], "project_stop", f"停止项目 #{project_id}；保留已保存结果")
        return database.one("SELECT * FROM projects WHERE id=?", (project_id,))

    @application.delete("/api/projects/{project_id}")
    async def delete(project_id: int, request: Request, database=Depends(db), user=Depends(current_user)):
        project_for(request, project_id, user)
        try:
            await request.app.state.runner.adelete(project_id)
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
        database.audit(user["id"], "project_delete", f"删除项目 #{project_id} 及关联数据；操作审计保留")
        return {"ok": True}

    def records_endpoint(table: str):
        def records(project_id: int, request: Request, after: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=2000), database=Depends(db), user=Depends(current_user)):
            project_for(request, project_id, user)
            return database.all(f"SELECT * FROM {table} WHERE project_id=? AND id>? ORDER BY id LIMIT ?", (project_id, after, limit))
        return records

    for endpoint, table in (("stages", "runtime_stages"), ("workers", "worker_tasks"), ("logs", "runtime_logs"), ("resources", "resource_usages"), ("messages", "chat_messages")):
        application.add_api_route(f"/api/projects/{{project_id}}/{endpoint}", records_endpoint(table), methods=["GET"], name=endpoint)

    @application.get("/api/projects/{project_id}/vulnerabilities")
    def vulnerabilities(project_id: int, request: Request, risk_level: Literal["critical", "high", "medium", "low", "info"] | None = None, verify_status: Literal["pending", "static_confirmed", "needs_review"] | None = None, database=Depends(db), user=Depends(current_user)):
        project_for(request, project_id, user)
        sql = "SELECT * FROM vulnerabilities WHERE project_id=?"
        params = [project_id]
        for column, value in (("risk_level", risk_level), ("verify_status", verify_status)):
            if value:
                sql += f" AND {column}=?"
                params.append(value)
        return database.all(sql + " ORDER BY id", params)

    @application.get("/api/projects/{project_id}/vulnerabilities/{vuln_id}")
    def vulnerability(project_id: int, vuln_id: int, request: Request, database=Depends(db), user=Depends(current_user)):
        project_for(request, project_id, user)
        row = database.one("SELECT * FROM vulnerabilities WHERE project_id=? AND id=?", (project_id, vuln_id))
        if not row:
            raise HTTPException(404, "漏洞记录不存在")
        return row

    @application.get("/api/projects/{project_id}/attack-paths")
    def attack_paths(project_id: int, request: Request, database=Depends(db), user=Depends(current_user)):
        project_for(request, project_id, user)
        rows = database.all("SELECT * FROM attack_paths WHERE project_id=? ORDER BY id", (project_id,))
        for row in rows:
            row["items"] = database.all("SELECT attack_path_items.*, vulnerabilities.vuln_code, vulnerabilities.vuln_title FROM attack_path_items JOIN vulnerabilities ON vulnerabilities.id=attack_path_items.vuln_id WHERE path_id=? ORDER BY step_order", (row["id"],))
        return rows

    @application.get("/api/projects/{project_id}/report")
    def report(project_id: int, request: Request, database=Depends(db), user=Depends(current_user)):
        project_for(request, project_id, user)
        row = database.one("SELECT * FROM reports WHERE project_id=? ORDER BY id DESC LIMIT 1", (project_id,))
        if not row:
            raise HTTPException(404, "报告尚未生成")
        return row

    @application.get("/api/projects/{project_id}/report/download")
    def download(project_id: int, request: Request, format: Literal["md", "html"] = "md", database=Depends(db), user=Depends(current_user)):
        row = report(project_id, request, database, user)
        content = row["report_markdown"] if format == "md" else row["report_html"]
        return Response(content, media_type="text/markdown" if format == "md" else "text/html", headers={"Content-Disposition": f'attachment; filename="assessment-{project_id}.{format}"'})

    @application.websocket("/api/projects/{project_id}/stream")
    async def stream(websocket: WebSocket, project_id: int):
        origin = websocket.headers.get("origin")
        if origin and urlsplit(origin).netloc != websocket.headers.get("host"):
            await websocket.close(code=4403)
            return
        database = websocket.app.state.db
        user = await asyncio.to_thread(session_user, database, websocket.cookies.get(COOKIE))
        project = await asyncio.to_thread(database.one, "SELECT * FROM projects WHERE id=?", (project_id,))
        if not user or not project or (user["role"] != "admin" and project["created_by"] != user["id"]):
            await websocket.close(code=4403)
            return
        entry = websocket.app.state.bus.subscribe(project_id)
        await websocket.accept()
        async def send_events():
            while True:
                if not await asyncio.to_thread(session_user, database, websocket.cookies.get(COOKIE)):
                    await websocket.close(code=4401)
                    return
                try:
                    event = await asyncio.wait_for(entry[1].get(), timeout=10)
                except asyncio.TimeoutError:
                    event = {"type": "heartbeat", "data": {"project_id": project_id}}
                await websocket.send_json(event)

        async def wait_disconnect():
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return

        tasks = []
        try:
            await websocket.send_json({"type": "project_status", "data": {"project_id": project_id, "project_status": project["project_status"]}})
            tasks = [asyncio.create_task(send_events()), asyncio.create_task(wait_disconnect())]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            websocket.app.state.bus.unsubscribe(project_id, entry)

    static = Path(__file__).with_name("static")
    application.mount("/static", StaticFiles(directory=static), name="static")

    @application.get("/", include_in_schema=False)
    def index():
        return FileResponse(static / "index.html")

    return application


app = create_app()
