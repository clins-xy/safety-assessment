import asyncio
import secrets
from pathlib import PurePosixPath

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.datastructures import UploadFile

from ...application.analysis.imports import MAX_UPLOAD_BYTES, collect_sources
from ...auth import current_user
from ...db import now


router = APIRouter(prefix="/api/projects", tags=["源码导入"])


@router.post("/import", status_code=202)
async def import_project(request: Request, user=Depends(current_user)):
    # Cap the actual stream, including chunked requests, before multipart parsing.
    chunks = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES + 1024 * 1024:
            raise HTTPException(413, "上传请求不能超过 21 MiB（源码或 ZIP 最多 20 MiB）")
        chunks.append(chunk)
    body = b"".join(chunks)
    del chunks
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}
    form_request = Request(request.scope, receive)
    database = request.app.state.db
    async with form_request.form(max_files=200, max_fields=8, max_part_size=4 * 1024 * 1024) as form:
        uploads = []
        upload_bytes = 0
        for upload in form.getlist("files"):
            if not isinstance(upload, UploadFile) or not upload.filename:
                raise HTTPException(422, "请选择需要评估的源码文件")
            data = await upload.read(MAX_UPLOAD_BYTES + 1)
            upload_bytes += len(data)
            if upload_bytes > MAX_UPLOAD_BYTES:
                raise HTTPException(413, "单次上传不能超过 20 MiB")
            uploads.append((upload.filename, data))
        def text(name, default=""):
            value = form.get(name, default)
            if not isinstance(value, str):
                raise HTTPException(422, f"{name} 必须是文本")
            return value
        project_name = text("project_name").strip()
        task_content = text("task_content").strip()
        if len(project_name) > 160 or len(task_content) > 10000:
            raise HTTPException(422, "项目名称或任务说明过长")
        settings = await database.aconfig()
        try:
            result = await asyncio.to_thread(collect_sources, uploads, text("code"), text("filename", "submitted.py"), settings["max_files"])
        except ValueError as error:
            raise HTTPException(422, str(error)) from None

    if not project_name:
        origin = uploads[0][0] if uploads else result.sources[0].filename
        origin = origin.replace("\\", "/")
        label = origin.split("/")[0] if "/" in origin else PurePosixPath(origin).stem
        project_name = (label + " · 安全评估")[:160]
    timestamp = now()
    def save():
        with database.connect() as connection:
            project_id = database.insert_on(connection, "projects", project_name=project_name, source_type="inline", source_path=f"uploaded://{len(result.sources)}-files", task_content=task_content or "上传源码安全评估", environment_type="static", environment_id="safety-" + secrets.token_hex(12), created_by=user["id"], created_at=timestamp, updated_at=timestamp)
            for source in result.sources:
                database.insert_on(connection, "code_submissions", project_id=project_id, filename=source.filename, language="python", code_text=source.code, created_at=timestamp)
            database.insert_on(connection, "audit_logs", user_id=user["id"], action="source_import", detail=f"项目 #{project_id} 导入 {len(result.sources)} 个 Python 文件，忽略 {result.skipped} 个非源码或依赖文件", created_at=timestamp)
            return project_id
    project_id = await asyncio.to_thread(save)
    started = True
    message = "源码已保存，评估已开始"
    try:
        await request.app.state.runner.astart(project_id)
    except ValueError as error:
        started = False
        message = f"源码已保存；{error}。可稍后在项目页启动评估。"
    return {"project_id": project_id, "project_name": project_name, "file_count": len(result.sources), "skipped_count": result.skipped, "bytes": sum(source.size for source in result.sources), "started": started, "message": message}
