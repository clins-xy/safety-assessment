import asyncio
import ast

from fastapi import APIRouter, Depends, HTTPException, Request

from ...auth import current_user
from ...db import now
from ...domain.schemas import CodeSubmission


router = APIRouter(prefix="/api/projects", tags=["代码提交"])


async def authorized_project(database, project_id, user):
    project = await database.aone("SELECT * FROM projects WHERE id=?", (project_id,))
    if not project:
        raise HTTPException(404, "项目不存在")
    if user["role"] != "admin" and project["created_by"] != user["id"]:
        raise HTTPException(403, "无权访问该项目")
    return project


@router.post("/{project_id}/submissions")
async def submit_code(project_id: int, body: CodeSubmission, request: Request, user=Depends(current_user)):
    database = request.app.state.db
    project = await authorized_project(database, project_id, user)
    if project["project_status"] not in ("created", "stopped", "failed"):
        raise HTTPException(409, "项目运行中，不能提交代码")
    if len(body.code.encode("utf-8")) > 1_048_576:
        raise HTTPException(422, "源码 UTF-8 大小不能超过 1 MiB")
    try:
        await asyncio.to_thread(ast.parse, body.code, filename=body.filename)
    except (SyntaxError, ValueError, RecursionError) as error:
        raise HTTPException(422, f"Python 源码无法解析：{error}") from None
    timestamp = now()
    def save_submission():
        with database.connect() as connection:
            submission_id = database.insert_on(connection, "code_submissions", project_id=project_id, filename=body.filename, language=body.language, code_text=body.code, created_at=timestamp)
            connection.execute("UPDATE projects SET source_type='inline', source_path=?, updated_at=? WHERE id=?", (f"submitted://{body.filename}", timestamp, project_id))
            return submission_id
    submission_id = await asyncio.to_thread(save_submission)
    await asyncio.to_thread(database.audit, user["id"], "code_submit", f"项目 #{project_id} 提交代码 #{submission_id}")
    analysis = await request.app.state.analysis_service.analyze_submission(project_id, submission_id, body.filename, body.code)
    log_id = await database.ainsert("runtime_logs", project_id=project_id, stage_id=None, worker_task_id=None, log_level="info", log_content=f"提交代码 #{submission_id} 分析完成：规则 {len(analysis['static'])} 条；LLM {analysis['llm_status']}", created_at=now())
    await database.ainsert("chat_messages", project_id=project_id, worker_role="analyst", message_type="submission_analysis", message_text=f"代码提交 #{submission_id} 已完成静态分析和可选模型复核。", created_at=now())
    request.app.state.bus.publish(project_id, "submission_analysis", {"submission_id": submission_id, "analysis_id": analysis["id"], "static_count": len(analysis["static"]), "llm_status": analysis["llm_status"]})
    return {"id": submission_id, "project_id": project_id, "filename": body.filename, "bytes": len(body.code.encode("utf-8")), "analysis": analysis}


@router.get("/{project_id}/submissions")
async def list_submissions(project_id: int, request: Request, user=Depends(current_user)):
    database = request.app.state.db
    await authorized_project(database, project_id, user)
    return await database.aall("SELECT id, project_id, filename, language, created_at FROM code_submissions WHERE project_id=? ORDER BY id DESC", (project_id,))


@router.get("/{project_id}/submissions/{submission_id}")
async def get_submission(project_id: int, submission_id: int, request: Request, user=Depends(current_user)):
    database = request.app.state.db
    await authorized_project(database, project_id, user)
    submission = await database.aone("SELECT * FROM code_submissions WHERE id=? AND project_id=?", (submission_id, project_id))
    if not submission:
        raise HTTPException(404, "代码提交不存在")
    return submission


@router.post("/{project_id}/submissions/{submission_id}/analyze")
async def analyze_existing(project_id: int, submission_id: int, request: Request, user=Depends(current_user)):
    database = request.app.state.db
    project = await authorized_project(database, project_id, user)
    if project["project_status"] in ("running", "completed"):
        raise HTTPException(409, "运行中或已生成报告的项目不能重新分析")
    submission = await database.aone("SELECT * FROM code_submissions WHERE id=? AND project_id=?", (submission_id, project_id))
    if not submission:
        raise HTTPException(404, "代码提交不存在")
    return await request.app.state.analysis_service.analyze_submission(project_id, submission["id"], submission["filename"], submission["code_text"])


@router.get("/{project_id}/submission-analyses")
async def list_submission_analyses(project_id: int, request: Request, user=Depends(current_user)):
    database = request.app.state.db
    await authorized_project(database, project_id, user)
    return await database.aall("SELECT submission_analyses.*, llm_analyses.status AS llm_status, llm_analyses.summary AS llm_summary, llm_analyses.result_json AS llm_result_json FROM submission_analyses LEFT JOIN llm_analyses ON llm_analyses.id=submission_analyses.llm_analysis_id WHERE submission_analyses.project_id=? ORDER BY submission_analyses.id DESC", (project_id,))
