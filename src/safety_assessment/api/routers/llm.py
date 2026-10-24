import json

from fastapi import APIRouter, Depends, HTTPException, Request

from ...auth import admin_user, current_user
from ...domain.schemas import LLMSettings, LLMSettingsResponse
from ...application.analysis import AnalysisService
from ...infrastructure.llm import LLMClient
from ...llm_settings import environment_overrides, load_llm_settings


router = APIRouter(prefix="/api/system/llm", tags=["大语言模型"])


def _settings(database) -> LLMSettings:
    return load_llm_settings(database)


def public(settings: LLMSettings) -> dict:
    return LLMSettingsResponse(
        enabled=settings.enabled, provider=settings.provider, base_url=settings.base_url, model=settings.model,
        timeout_seconds=settings.timeout_seconds, max_code_chars=settings.max_code_chars,
        system_prompt=settings.system_prompt, api_key_configured=bool(settings.api_key),
        environment_overrides=list(environment_overrides()),
    ).model_dump()


@router.get("/config")
def get_config(request: Request, user=Depends(admin_user)):
    return public(_settings(request.app.state.db))


@router.put("/config")
def put_config(body: LLMSettings, request: Request, user=Depends(admin_user)):
    database = request.app.state.db
    overrides = environment_overrides()
    effective = LLMSettings.model_validate({**body.model_dump(), **overrides})
    if not effective.api_key:
        effective.api_key = _settings(database).api_key
    if effective.enabled and not effective.api_key:
        raise HTTPException(422, "启用大语言模型前请先配置 API Key")
    if not body.api_key:
        body.api_key = database.config().get("llm_api_key", "")
    values = {
        "llm_enabled": body.enabled, "llm_provider": body.provider, "llm_base_url": body.base_url,
        "llm_api_key": body.api_key, "llm_model": body.model, "llm_timeout_seconds": body.timeout_seconds,
        "llm_max_code_chars": body.max_code_chars, "llm_system_prompt": body.system_prompt,
    }
    with database.connect() as connection:
        for key, value in values.items():
            if key.removeprefix("llm_") in overrides:
                continue
            connection.execute("UPDATE system_config SET value=? WHERE `key`=?", (json.dumps(value), key))
    settings = _settings(database)
    request.app.state.analysis_service = AnalysisService(database, LLMClient(settings) if settings.enabled else None)
    request.app.state.runner.analysis_service = request.app.state.analysis_service
    database.audit(user["id"], "llm_config_update", "更新大语言模型配置；密钥不返回前端")
    return public(settings)


@router.get("/health")
async def health(request: Request, user=Depends(current_user)):
    settings = _settings(request.app.state.db)
    if not settings.enabled:
        return {"enabled": False, "reachable": False, "message": "大语言模型未启用"}
    if not settings.api_key:
        raise HTTPException(422, "已启用大语言模型，但未配置 API Key")
    return {"enabled": True, "configured": True, "reachable": None, "message": "已配置，尚未测试连接"}


@router.post("/test")
async def test_connection(request: Request, user=Depends(admin_user)):
    settings = _settings(request.app.state.db)
    if not settings.enabled or not settings.api_key:
        raise HTTPException(422, "请先启用大语言模型并配置 API Key")
    try:
        await LLMClient(settings).review("connection_test.py", "# Connection test\nprint('hello')\n")
    except ValueError as error:
        return {"enabled": True, "reachable": False, "message": str(error)}
    return {"enabled": True, "reachable": True, "message": "连接成功，模型已返回有效的 JSON 审查结果"}
