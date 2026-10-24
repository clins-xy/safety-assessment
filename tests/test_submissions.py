import pytest


def project(client):
    source = client.get("/api/examples").json()[0]
    response = client.post("/api/projects", json={"project_name": "inline submission", "source_type": "inline", "source_path": "", "task_content": "inline"})
    assert response.status_code == 201
    return response.json()


def test_code_submission_is_analyzed_and_persisted(admin):
    client = admin
    created = project(client)
    prefix = f"/api/projects/{created['id']}"
    code = "import os\ndef run(value):\n    os.system(value)\n"
    response = client.post(prefix + "/submissions", json={"filename": "review.py", "language": "python", "code": code})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["analysis"]["static"][0]["rule_id"] == "COMMAND_INJECTION"
    assert result["analysis"]["llm_status"] == "disabled"
    assert client.get(prefix + "/submissions").json()[0]["filename"] == "review.py"
    analyses = client.get(prefix + "/submission-analyses").json()
    assert analyses[0]["submission_id"] == result["id"]
    assert client.app.state.db.all("SELECT * FROM llm_analyses WHERE project_id=?", (created["id"],))[0]["status"] == "disabled"
    findings = client.get(prefix + "/vulnerabilities").json()
    assert any(item["vuln_code"].startswith("S-") for item in findings)


def test_llm_config_never_returns_key(admin):
    client = admin
    config = client.get("/api/system/llm/config")
    assert config.status_code == 200
    payload = {**config.json(), "enabled": True, "api_key": "secret-test-key", "system_prompt": "请只返回 JSON 安全审查结果。"}
    assert client.put("/api/system/llm/config", json=payload).status_code == 200
    response = client.get("/api/system/llm/config").json()
    assert response["api_key_configured"] is True
    assert "api_key" not in response
    assert "llm_api_key" not in client.get("/api/system/config").json()
    assert client.get("/api/system/llm/health").json()["reachable"] is None
    saved = client.put("/api/system/config", json=client.get("/api/system/config").json())
    assert "llm_api_key" not in saved.json()
    assert "secret-test-key" not in saved.text


def test_submission_rejects_unsafe_filename(admin):
    created = project(admin)
    for filename in ("../secret.py", ".", "..", ".py", "review.txt"):
        response = admin.post(f"/api/projects/{created['id']}/submissions", json={"filename": filename, "code": "print(1)"})
        assert response.status_code == 422


def test_submission_round_trip_and_reanalysis(admin):
    created = project(admin)
    prefix = f"/api/projects/{created['id']}"
    code = "# 中文源码与引号：' ? % \' OR 1=1; --\nimport os\ndef run(value):\n    os.system(value)\n"
    result = admin.post(prefix + "/submissions", json={"filename": "saved.py", "code": code}).json()
    saved = admin.get(prefix + f"/submissions/{result['id']}")
    assert saved.json()["code_text"] == code
    assert admin.app.state.db.one("SELECT code_text FROM code_submissions WHERE id=?", (result["id"],))["code_text"] == code
    assert admin.post(prefix + f"/submissions/{result['id']}/analyze").status_code == 200
    assert len(admin.get(prefix + "/vulnerabilities").json()) == 1
    assert len(admin.get(prefix + "/submission-analyses").json()) == 2


def test_invalid_code_is_rejected_before_write(admin):
    created = project(admin)
    prefix = f"/api/projects/{created['id']}"
    assert admin.post(prefix + "/submissions", json={"code": "def broken("}).status_code == 422
    assert admin.get(prefix + "/submissions").json() == []
    assert admin.post(prefix + "/submissions", json={"code": "#" + "\u4e2d" * 350000}).status_code == 422


def test_inline_submission_can_generate_report(admin):
    from tests.test_system import wait_done

    created = project(admin)
    prefix = f"/api/projects/{created['id']}"
    submitted = admin.post(prefix + "/submissions", json={"code": "import os\ndef run(value):\n    os.system(value)\n"})
    assert submitted.status_code == 200
    assert admin.post(prefix + "/start").status_code == 200
    assert wait_done(admin, created["id"])["project_status"] == "completed"
    assert len(admin.get(prefix + "/vulnerabilities").json()) == 1
    assert "大语言模型复核" in admin.get(prefix + "/report").json()["report_markdown"]


def test_inline_empty_project_cannot_start(admin):
    created = project(admin)
    prefix = f"/api/projects/{created['id']}"
    assert admin.post(prefix + "/start").status_code == 409
    assert admin.get(prefix).json()["project_status"] == "created"


def test_llm_requires_key_and_valid_url(admin):
    config = admin.get("/api/system/llm/config").json()
    assert admin.put("/api/system/llm/config", json={**config, "enabled": True}).status_code == 422
    for url in ("file:///tmp/model", "https://user:secret@example.com/v1", "https://example.com/v1?api_key=secret"):
        assert admin.put("/api/system/llm/config", json={**config, "base_url": url}).status_code == 422
