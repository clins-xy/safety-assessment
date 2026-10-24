import os

from .domain.schemas import LLMSettings


ENV_FIELDS = {
    name: f"SAFETY_LLM_{name.upper()}"
    for name in LLMSettings.model_fields
}


def environment_overrides() -> dict[str, str]:
    # Blank entries are placeholders: they must not disable configuration in the UI.
    return {
        name: os.environ[variable].strip()
        for name, variable in ENV_FIELDS.items()
        if os.environ.get(variable, "").strip()
    }


def load_llm_settings(database) -> LLMSettings:
    values = database.config()
    settings = {
        name: values[f"llm_{name}"]
        for name in LLMSettings.model_fields
        if f"llm_{name}" in values
    }
    default_prompt = LLMSettings.model_fields["system_prompt"].default
    if settings.get("system_prompt") == default_prompt.replace("JSON 对象", "JSON 数组"):
        settings["system_prompt"] = default_prompt
    settings.update(environment_overrides())
    return LLMSettings.model_validate(settings)
