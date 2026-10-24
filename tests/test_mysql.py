import os
import secrets
import time
import json
import re
from io import BytesIO
from zipfile import ZipFile

import httpx
import pytest
from fastapi.testclient import TestClient

from safety_assessment.app import create_app
from safety_assessment.auth import password_hash
from safety_assessment.db import Database, now
from safety_assessment.application.analysis import AnalysisService
from safety_assessment.domain.schemas import LLMSettings
from safety_assessment.infrastructure.llm import LLMClient


@pytest.mark.skipif(os.environ.get("SAFETY_TEST_MYSQL") != "1", reason="显式设置 SAFETY_TEST_MYSQL=1 后运行真实数据库集成测试")
def test_mysql_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFETY_DB_BACKEND", "mysql")
    database = Database(tmp_path / "mysql-runtime")
    tables_before = database.all("SHOW TABLES")
    definitions_before = {next(iter(row.values())): database.all(f"SHOW CREATE TABLE `{next(iter(row.values()))}`") for row in tables_before}
    assert not database.one("SELECT id FROM projects WHERE project_status='running'"), "请等待现有评估完成后运行集成测试"
    username = "integration_" + secrets.token_hex(8)
    password = secrets.token_urlsafe(24)
    user_id = database.insert("users", username=username, password_hash=password_hash(password), role="admin", created_at=now())
    created = []
    try:
        with TestClient(create_app(tmp_path / "mysql-runtime")) as client:
            assert client.post("/api/system/login", json={"username": username, "password": password}).status_code == 200
            for example in client.get("/api/examples").json():
                response = client.post("/api/projects", json={"project_name": "MySQL integration " + example["name"], "source_path": example["path"], "source_type": "local"})
                assert response.status_code == 201, response.text
                project_id = response.json()["id"]
                created.append(project_id)
                prefix = f"/api/projects/{project_id}"
                assert client.post(prefix + "/start").status_code == 200
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    project = client.get(prefix).json()
                    if project["project_status"] != "running":
                        break
                    time.sleep(0.05)
                assert project["project_status"] == "completed", project
                assert len(client.get(prefix + "/vulnerabilities").json()) == example["expected_findings"]
                assert len(client.get(prefix + "/attack-paths").json()) == example["expected_findings"]
                assert client.get(prefix + "/report/download").status_code == 200
                config = client.get("/api/system/config").json()
                assert client.put("/api/system/config", json=config).status_code == 200

            inline = client.post("/api/projects", json={"project_name": "MySQL code persistence check", "source_type": "inline"})
            assert inline.status_code == 201, inline.text
            project_id = inline.json()["id"]
            created.append(project_id)
            prefix = f"/api/projects/{project_id}"
            code = "# 中文与引号 ' ? % ; --\nimport os\ndef run(value):\n    os.system(value)\n"
            original_client = httpx.AsyncClient
            provider_status = [200]
            def respond(request):
                assert request.headers["authorization"] == "Bearer mysql-test-key"
                if provider_status[0] != 200:
                    return httpx.Response(provider_status[0])
                return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"summary": "模型复核已完成", "findings": []}, ensure_ascii=False)}}]})
            monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original_client(transport=httpx.MockTransport(respond), **kwargs))
            client.app.state.analysis_service = AnalysisService(database, LLMClient(LLMSettings(enabled=True, api_key="mysql-test-key", base_url="https://model.example/v1")))
            submitted = client.post(prefix + "/submissions", json={"filename": "roundtrip.py", "code": code})
            assert submitted.status_code == 200, submitted.text
            submission_id = submitted.json()["id"]
            assert submitted.json()["analysis"]["llm_status"] == "success"
            assert database.one("SELECT code_text FROM code_submissions WHERE id=?", (submission_id,))["code_text"] == code
            assert client.get(prefix + f"/submissions/{submission_id}").json()["code_text"] == code
            assert database.one("SELECT status FROM llm_analyses WHERE submission_id=?", (submission_id,))["status"] == "success"
            provider_status[0] = 401
            retried = client.post(prefix + f"/submissions/{submission_id}/analyze")
            assert retried.status_code == 200, retried.text
            assert retried.json()["llm_status"] == "failed"
            assert len(client.get(prefix + "/vulnerabilities").json()) == 1
            assert len(client.get(prefix + "/submission-analyses").json()) == 2
            assert client.post(prefix + "/start").status_code == 200
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                result = client.get(prefix).json()
                if result["project_status"] != "running":
                    break
                time.sleep(0.05)
            assert result["project_status"] == "completed", result
            assert "大语言模型复核" in client.get(prefix + "/report").json()["report_markdown"]
            zipped = BytesIO()
            with ZipFile(zipped, "w") as archive:
                archive.writestr("uploaded/api/中文.py", code)
                archive.writestr("uploaded/worker/app.py", "print('safe')\n")
            imported = client.post("/api/projects/import", files={"files": ("upload.zip", zipped.getvalue(), "application/zip")})
            assert imported.status_code == 202, imported.text
            imported_id = imported.json()["project_id"]
            created.append(imported_id)
            assert imported.json()["started"]
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                uploaded = client.get(f"/api/projects/{imported_id}").json()
                if uploaded["project_status"] != "running":
                    break
                time.sleep(0.05)
            assert uploaded["project_status"] == "completed", uploaded
            saved_files = database.all("SELECT filename,code_text FROM code_submissions WHERE project_id=? ORDER BY filename", (imported_id,))
            assert len(saved_files) == 2
            assert saved_files[0]["filename"] == "uploaded/api/中文.py"
            assert saved_files[0]["code_text"] == code
            assert client.get(f"/api/projects/{imported_id}/report/download").status_code == 200
            for table in ("projects", "code_submissions", "submission_analyses", "llm_analyses", "runtime_stages", "worker_tasks", "vulnerabilities", "attack_paths", "chat_messages", "runtime_logs", "resource_usages", "reports"):
                key = "id" if table == "projects" else "project_id"
                for row in database.all(f"SELECT * FROM `{table}` WHERE `{key}`=?", (imported_id,)):
                    for column, value in row.items():
                        if column in ("created_at", "updated_at", "started_at", "finished_at", "recorded_at") and value is not None:
                            assert re.fullmatch(r"\d{4}/\d{2}/\d{2}/\d{2}\.\d{2}", value), (table, column, value)
            runner = client.app.state.runner
            for project_id in created:
                with runner.lock:
                    job = runner.jobs.get(project_id)
                if job:
                    job[1].result(timeout=5)
                assert client.delete(f"/api/projects/{project_id}").status_code == 200
            assert client.post("/api/system/logout").status_code == 200
    finally:
        for project_id in created:
            database.execute("DELETE FROM projects WHERE id=?", (project_id,))
        database.execute("DELETE FROM users WHERE id=?", (user_id,))
        assert database.all("SHOW TABLES") == tables_before
        for table, definition in definitions_before.items():
            # AUTO_INCREMENT counters may advance when temporary records are tested.
            normalize = lambda value: re.sub(r"AUTO_INCREMENT=\d+", "AUTO_INCREMENT=N", str(value))
            assert normalize(database.all(f"SHOW CREATE TABLE `{table}`")) == normalize(definition)
