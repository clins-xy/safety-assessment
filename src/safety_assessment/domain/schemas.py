from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CodeSubmission(BaseModel):
    filename: str = Field(default="submitted.py", min_length=1, max_length=180, pattern=r"^[A-Za-z0-9_.-]+$")
    code: str = Field(min_length=1, max_length=1_048_576)
    language: Literal["python"] = "python"

    @field_validator("filename")
    @classmethod
    def python_filename(cls, value: str) -> str:
        if not value.endswith(".py") or value == ".py":
            raise ValueError("请使用有效的 .py 文件名")
        return value


class CodeSubmissionResponse(BaseModel):
    id: int
    project_id: int
    filename: str
    bytes: int


class SubmissionAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    submission_id: int = Field(ge=1)


class LLMSettings(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = False
    provider: Literal["openai_compatible"] = "openai_compatible"
    base_url: str = Field("https://api.openai.com/v1", min_length=1, max_length=500)
    api_key: str = Field(default="", max_length=500)
    model: str = Field("gpt-4o-mini", min_length=1, max_length=160)
    timeout_seconds: int = Field(45, ge=5, le=300)
    max_code_chars: int = Field(12000, ge=1000, le=50000)
    system_prompt: str = Field("你是代码安全审查助手。只分析输入源码，返回严格 JSON 对象；不要执行代码，不要编造证据。", min_length=10, max_length=4000)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        try:
            url = urlsplit(value)
            valid = url.scheme in ("http", "https") and url.hostname and url.port != 0
        except ValueError:
            valid = False
        if not valid or url.username is not None or url.password is not None or url.query or url.fragment:
            raise ValueError("Base URL 必须是无凭据、查询参数和片段的 HTTP(S) 地址")
        return value

    @field_validator("model", "api_key")
    @classmethod
    def strip_setting(cls, value: str) -> str:
        value = value.strip()
        if "\r" in value or "\n" in value:
            raise ValueError("配置不能包含换行符")
        return value

    @field_validator("model")
    @classmethod
    def nonblank_model(cls, value: str) -> str:
        if not value:
            raise ValueError("模型名称不能为空")
        return value


class LLMSettingsResponse(BaseModel):
    enabled: bool
    provider: str
    base_url: str
    model: str
    timeout_seconds: int
    max_code_chars: int
    system_prompt: str
    api_key_configured: bool
    environment_overrides: list[str] = Field(default_factory=list)


class LLMFinding(BaseModel):
    rule_id: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=255)
    risk_level: Literal["critical", "high", "medium", "low", "info"]
    file_path: str = Field(min_length=1, max_length=500)
    line_number: int = Field(ge=1)
    impact: str = Field(min_length=1, max_length=4000)
    condition: str = Field(min_length=1, max_length=4000)
    remediation: str = Field(min_length=1, max_length=4000)
    confidence: float = Field(ge=0, le=1)
    evidence: str = Field(default="", max_length=6000)


class LLMReview(BaseModel):
    summary: str = Field(default="", max_length=8000)
    findings: list[LLMFinding] = Field(default_factory=list, max_length=100)
