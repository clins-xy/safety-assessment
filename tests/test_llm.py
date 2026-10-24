import json

import httpx
import pytest

from safety_assessment.domain.schemas import LLMSettings
from safety_assessment.llm_settings import load_llm_settings


def mock_provider(monkeypatch, handler):
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))


def configure(client):
    config = client.get("/api/system/llm/config").json()
    response = client.put("/api/system/llm/config", json={**config, "enabled": True, "api_key": "secret-test-key", "base_url": "https://model.example/v1", "model": "test-model"})
    assert response.status_code == 200, response.text


def create_project(client):
    return client.post("/api/projects", json={"project_name": "LLM integration", "source_type": "inline"}).json()["id"]


def test_llm_request_and_database_round_trip(admin, monkeypatch):
    requests = []
    finding = {"rule_id": "COMMAND_INJECTION", "title": "Shell injection", "risk_level": "critical", "file_path": "review.py", "line_number": 3, "impact": "Command execution", "condition": "External input", "remediation": "Use argv", "confidence": 0.9, "evidence": "os.system(value)"}
    def respond(request):
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"summary": "Review complete", "findings": [finding]})}}]})
    mock_provider(monkeypatch, respond)
    configure(admin)
    project_id = create_project(admin)
    response = admin.post(f"/api/projects/{project_id}/submissions", json={"filename": "review.py", "code": "import os\ndef run(value):\n    os.system(value)\n"})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["analysis"]["llm_status"] == "success"
    request = requests[0]
    assert str(request.url) == "https://model.example/v1/chat/completions"
    assert request.headers["authorization"] == "Bearer secret-test-key"
    assert json.loads(request.content)["model"] == "test-model"
    database = admin.app.state.db
    row = database.one("SELECT * FROM llm_analyses WHERE submission_id=?", (result["id"],))
    assert json.loads(row["result_json"])["findings"][0]["risk_level"] == "critical"
    vulnerability = database.one("SELECT * FROM vulnerabilities WHERE project_id=? AND rule_id LIKE 'LLM:%'", (project_id,))
    assert vulnerability["risk_level"] == "critical"
    assert vulnerability["verify_status"] == "needs_review"
    assert "secret-test-key" not in response.text


@pytest.mark.parametrize("mode", ["unauthorized", "timeout", "bad_json", "wrong_location"])
def test_llm_failures_preserve_code_and_static_analysis(admin, monkeypatch, mode):
    def respond(request):
        if mode == "timeout":
            raise httpx.ReadTimeout("secret-test-key", request=request)
        if mode == "unauthorized":
            return httpx.Response(401, text="secret-test-key")
        content = "secret-test-key"
        if mode == "wrong_location":
            content = json.dumps({"summary": "Review", "findings": [{"rule_id": "X", "title": "X", "risk_level": "high", "file_path": "other.py", "line_number": 999, "impact": "X", "condition": "X", "remediation": "X", "confidence": 1}]})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})
    mock_provider(monkeypatch, respond)
    configure(admin)
    project_id = create_project(admin)
    code = "import os\ndef run(value):\n    os.system(value)\n"
    response = admin.post(f"/api/projects/{project_id}/submissions", json={"code": code})
    assert response.status_code == 200
    result = response.json()
    assert result["analysis"]["llm_status"] == "failed"
    assert len(result["analysis"]["static"]) == 1
    assert "secret-test-key" not in response.text
    database = admin.app.state.db
    assert database.one("SELECT code_text FROM code_submissions WHERE id=?", (result["id"],))["code_text"] == code
    assert database.one("SELECT status FROM llm_analyses WHERE submission_id=?", (result["id"],))["status"] == "failed"


def test_connection_test_actually_calls_provider(admin, monkeypatch):
    seen = []
    def respond(request):
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"summary":"ok","findings":[]}'}}]})
    mock_provider(monkeypatch, respond)
    configure(admin)
    assert admin.get("/api/system/llm/health").json()["reachable"] is None
    assert seen == []
    assert admin.post("/api/system/llm/test").json()["reachable"] is True
    assert len(seen) == 1


def test_failed_connection_does_not_claim_success(admin, monkeypatch):
    mock_provider(monkeypatch, lambda request: httpx.Response(401, text="secret-test-key"))
    configure(admin)
    response = admin.post("/api/system/llm/test")
    assert response.json()["reachable"] is False
    assert "401" in response.json()["message"]
    assert "secret-test-key" not in response.text


def test_environment_settings_override_database_without_exposing_key(admin, monkeypatch):
    configure(admin)
    monkeypatch.setenv("SAFETY_LLM_API_KEY", "environment-secret")
    monkeypatch.setenv("SAFETY_LLM_BASE_URL", "https://environment.example/v1")
    monkeypatch.setenv("SAFETY_LLM_MODEL", "environment-model")
    monkeypatch.setenv("SAFETY_LLM_ENABLED", "true")
    effective = load_llm_settings(admin.app.state.db)
    assert effective.api_key == "environment-secret"
    config = admin.get("/api/system/llm/config")
    assert config.json()["base_url"] == "https://environment.example/v1"
    assert "environment-secret" not in config.text
    response = admin.put("/api/system/llm/config", json={**config.json(), "model": "ignored"})
    assert response.json()["model"] == "environment-model"
    assert admin.app.state.db.config()["llm_api_key"] == "secret-test-key"


def test_analysis_transaction_rolls_back_on_storage_failure(admin, monkeypatch):
    project_id = create_project(admin)
    database = admin.app.state.db
    original = database.insert_on
    def fail(connection, table, **values):
        if table == "submission_analyses":
            raise RuntimeError("simulated database failure")
        return original(connection, table, **values)
    monkeypatch.setattr(database, "insert_on", fail)
    with pytest.raises(RuntimeError, match="simulated database failure"):
        admin.post(f"/api/projects/{project_id}/submissions", json={"code": "import os\ndef run(value):\n    os.system(value)\n"})
    assert database.one("SELECT id FROM code_submissions WHERE project_id=?", (project_id,))
    assert database.all("SELECT * FROM llm_analyses WHERE project_id=?", (project_id,)) == []
    assert database.all("SELECT * FROM vulnerabilities WHERE project_id=?", (project_id,)) == []
