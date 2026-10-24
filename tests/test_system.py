import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from safety_assessment.environment import Cancelled, Environment, checked_local_path, remove_tree


def create_project(client, index=0):
    example = client.get("/api/examples").json()[index]
    response = client.post("/api/projects", json={"project_name": example["name"], "source_type": "local", "source_path": example["path"], "task_content": "自动化正反案例测试", "environment_type": "static"})
    assert response.status_code == 201, response.text
    return response.json()


def wait_done(client, project_id):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        project = client.get(f"/api/projects/{project_id}").json()
        if project["project_status"] != "running":
            return project
        time.sleep(0.03)
    pytest.fail("评估超时")


def test_auth_and_security(client):
    assert client.get("/api/projects").status_code == 401
    assert client.get("/api/system/status").json()["initialized"] is False
    credentials = {"username": "admin", "password": "strong-password"}
    assert client.post("/api/system/init", json=credentials).status_code == 201
    assert client.post("/api/system/init", json=credentials).status_code == 409
    assert client.post("/api/system/login", json={**credentials, "password": "wrong-password"}).status_code == 401
    login = client.post("/api/system/login", json=credentials)
    assert "HttpOnly" in login.headers["set-cookie"]
    assert "SameSite=strict" in login.headers["set-cookie"]
    assert client.get("/api/system/me").json()["role"] == "admin"
    assert client.post("/api/system/logout", headers={"origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/system/logout").status_code == 200
    assert client.get("/api/system/me").status_code == 401


@pytest.mark.parametrize("index,expected", [(0, 2), (1, 0)])
def test_full_pipeline_and_cascade(admin, index, expected):
    client = admin
    project = create_project(client, index)
    project_id = project["id"]
    prefix = f"/api/projects/{project_id}"
    assert client.get(prefix + "/report").status_code == 404
    with client.websocket_connect(prefix + "/stream") as stream:
        assert stream.receive_json()["type"] == "project_status"
        assert client.post(prefix + "/start").status_code == 200
        result = wait_done(client, project_id)
        assert result["project_status"] == "completed", result
    assert client.post(prefix + "/start").status_code == 409
    stages = client.get(prefix + "/stages").json()
    assert len(stages) == 5
    assert all(stage["stage_status"] == "success" for stage in stages)
    workers = client.get(prefix + "/workers").json()
    assert len({worker["worker_role"] for worker in workers}) == 6
    assert all(worker["task_status"] == "success" and worker["stage_id"] and worker["started_at"] and worker["finished_at"] for worker in workers)
    findings = client.get(prefix + "/vulnerabilities").json()
    assert len(findings) == expected
    assert all(finding["verify_status"] == "static_confirmed" for finding in findings)
    if findings:
        assert client.get(prefix + f"/vulnerabilities/{findings[0]['id']}").status_code == 200
        assert len(client.get(prefix + "/vulnerabilities?risk_level=critical").json()) == 1
    assert len(client.get(prefix + "/attack-paths").json()) == expected
    assert client.get(prefix + "/logs").json()
    assert client.get(prefix + "/resources").json()
    assert len(client.get(prefix + "/messages").json()) == 6
    report = client.get(prefix + "/report").json()
    assert "风险结论" in report["report_markdown"]
    assert "static_confirmed" in report["report_markdown"]
    assert client.get(prefix + "/report/download?format=html").headers["content-disposition"].endswith('.html"')
    runner = client.app.state.runner
    with runner.lock:
        job = runner.jobs.get(project_id)
    if job:
        job[1].result(timeout=5)
    assert client.delete(prefix).status_code == 200
    assert client.get(prefix).status_code == 404
    database = client.app.state.db
    for table in ("runtime_stages", "worker_tasks", "vulnerabilities", "attack_paths", "chat_messages", "runtime_logs", "resource_usages", "reports"):
        assert database.all(f"SELECT * FROM {table} WHERE project_id=?", (project_id,)) == []
    for directory in ("runtime_logs", "reports", "workspace"):
        assert not (database.root / directory / str(project_id)).exists()
    assert database.one("SELECT id FROM audit_logs WHERE action='project_delete'")


def test_permissions(admin):
    client = admin
    project = create_project(client)
    credentials = {"username": "regular_user", "password": "regular-password"}
    assert client.post("/api/system/users", json=credentials).status_code == 201
    with TestClient(client.app) as other:
        assert other.post("/api/system/login", json=credentials).status_code == 200
        assert other.get("/api/projects").json() == []
        assert other.get(f"/api/projects/{project['id']}").status_code == 403
        assert other.post(f"/api/projects/{project['id']}/start").status_code == 403
        assert other.get("/api/system/config").status_code == 403
        with pytest.raises(WebSocketDisconnect):
            with other.websocket_connect(f"/api/projects/{project['id']}/stream"):
                pass


def test_stop_keeps_partial_results(admin, monkeypatch):
    entered = threading.Event()
    original = Environment.prepare

    def slow_prepare(environment):
        entered.set()
        while not environment.cancel.wait(0.02):
            environment.check()
        environment.check()
        return original(environment)

    monkeypatch.setattr(Environment, "prepare", slow_prepare)
    project_id = create_project(admin)["id"]
    prefix = f"/api/projects/{project_id}"
    assert admin.post(prefix + "/start").status_code == 200
    assert entered.wait(3)
    assert admin.delete(prefix).status_code == 409
    result = admin.post(prefix + "/stop")
    assert result.status_code == 200
    assert result.json()["project_status"] == "stopped"
    assert admin.get(prefix + "/logs").json()
    assert not admin.get(prefix + "/vulnerabilities").json()
    assert any(worker["task_status"] == "failed" for worker in admin.get(prefix + "/workers").json())
    assert all(stage["stage_status"] == "idle" for stage in admin.get(prefix + "/stages").json()[1:])
    assert admin.delete(prefix).status_code == 200


def test_failure_is_saved(admin, monkeypatch):
    def fail_prepare(environment):
        raise RuntimeError("模拟环境准备失败")

    monkeypatch.setattr(Environment, "prepare", fail_prepare)
    project_id = create_project(admin)["id"]
    prefix = f"/api/projects/{project_id}"
    admin.post(prefix + "/start")
    result = wait_done(admin, project_id)
    assert result["project_status"] == "failed"
    assert "模拟环境准备失败" in result["error_message"]
    assert admin.get(prefix + "/workers").json()[-1]["error_message"]


def test_config_and_limits(admin):
    config = admin.get("/api/system/config").json()
    assert admin.put("/api/system/config", json={**config, "max_concurrency": 0}).status_code == 422
    assert admin.put("/api/system/config", json={**config, "default_timeout": 30}).status_code == 200
    assert admin.get("/api/system/config").json()["default_timeout"] == 30
    assert admin.get("/api/system/logs").json()
    assert admin.get("/").status_code == 200
    assert admin.get("/static/app.js").status_code == 200
    assert admin.get("/openapi.json").status_code == 200


def test_path_boundaries(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("SAFETY_SOURCE_ROOTS", str(allowed))
    assert checked_local_path(str(allowed), tmp_path / "data") == allowed
    with pytest.raises(ValueError):
        checked_local_path(str(tmp_path), tmp_path / "data")
    with pytest.raises(ValueError):
        remove_tree(tmp_path, allowed)
    with pytest.raises(ValueError):
        remove_tree(allowed, allowed)
