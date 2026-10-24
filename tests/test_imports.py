from io import BytesIO
import json
import stat
from zipfile import ZipFile, ZipInfo

import httpx
import pytest

from safety_assessment.application.analysis.imports import collect_sources, source_filename
from tests.test_system import wait_done


UNSAFE = "# 中文源码\nimport os\ndef run(value):\n    os.system(value)\n"
SAFE = "print('hello')\n"


def archive(files):
    buffer = BytesIO()
    with ZipFile(buffer, "w") as output:
        for filename, code in files:
            output.writestr(filename, code)
    return buffer.getvalue()


def test_uploaded_file_creates_project_analyzes_and_reports(admin):
    response = admin.post("/api/projects/import", files=[("files", ("示例.py", UNSAFE.encode(), "text/x-python"))])
    assert response.status_code == 202, response.text
    result = response.json()
    assert result["started"] is True
    assert result["file_count"] == 1
    prefix = f"/api/projects/{result['project_id']}"
    assert wait_done(admin, result["project_id"])["project_status"] == "completed"
    database = admin.app.state.db
    saved = database.one("SELECT * FROM code_submissions WHERE project_id=?", (result["project_id"],))
    assert saved["code_text"] == UNSAFE
    assert saved["filename"] == "示例.py"
    assert len(admin.get(prefix + "/vulnerabilities").json()) == 1
    assert len(admin.get(prefix + "/attack-paths").json()) == 1
    assert admin.get(prefix + "/submission-analyses").json()[0]["llm_status"] == "disabled"
    assert "示例.py" in admin.get(prefix + "/report").json()["report_markdown"]
    assert admin.get(prefix + "/report/download").status_code == 200


def test_zip_preserves_paths_and_same_basename_without_directory_config(admin, monkeypatch):
    monkeypatch.setenv("SAFETY_SOURCE_ROOTS", "Z:\\not-a-real-directory")
    data = archive([("project/api/app.py", UNSAFE), ("project/worker/app.py", SAFE), ("project/README.md", "README"), ("project/.venv/dependency.py", UNSAFE)])
    response = admin.post("/api/projects/import", files={"files": ("project.zip", data, "application/zip")})
    assert response.status_code == 202, response.text
    result = response.json()
    assert result["file_count"] == 2
    assert result["skipped_count"] == 2
    assert wait_done(admin, result["project_id"])["project_status"] == "completed"
    rows = admin.app.state.db.all("SELECT * FROM code_submissions WHERE project_id=? ORDER BY filename", (result["project_id"],))
    assert [row["filename"] for row in rows] == ["project/api/app.py", "project/worker/app.py"]
    assert rows[0]["code_text"] == UNSAFE
    findings = admin.get(f"/api/projects/{result['project_id']}/vulnerabilities").json()
    assert findings[0]["file_path"] == "project/api/app.py"


def test_folder_upload_and_pasted_code(admin):
    response = admin.post("/api/projects/import", files=[("files", ("my-project/api/main.py", SAFE)), ("files", ("my-project/tasks/任务.py", SAFE))], data={"project_name": "目录评估", "task_content": "关注命令注入"})
    assert response.status_code == 202, response.text
    project_id = response.json()["project_id"]
    assert wait_done(admin, project_id)["project_status"] == "completed"
    pasted = admin.post("/api/projects/import", files={"code": (None, UNSAFE), "filename": (None, "pasted.py")})
    assert pasted.status_code == 202, pasted.text
    assert wait_done(admin, pasted.json()["project_id"])["project_status"] == "completed"


@pytest.mark.parametrize("data", [
    archive([("../escaped.py", SAFE)]),
    archive([("C:/escaped.py", SAFE)]),
    archive([("/escaped.py", SAFE)]),
    archive([("app.py", SAFE), ("APP.py", SAFE)]),
    archive([("a.py", SAFE), ("a.py/nested.py", SAFE)]),
    archive([("app.py", "def broken(")]),
    archive([("app.py", b"\xff\xfe")]),
    archive([("README.md", "no source")]),
    b"not a zip",
])
def test_invalid_zip_is_rejected_without_creating_project(admin, data):
    before = admin.get("/api/projects").json()
    response = admin.post("/api/projects/import", files={"files": ("bad.zip", data)})
    assert response.status_code == 422, response.text
    assert admin.get("/api/projects").json() == before


@pytest.mark.parametrize("path", ["../a.py", "/tmp/a.py", "C:\\a.py", "foo//a.py", "foo/./a.py", "foo/CON.py", "foo /a.py", "foo/evil?.py", "file.txt"])
def test_import_path_rejects_traversal_and_windows_aliases(path):
    with pytest.raises(ValueError):
        source_filename(path)


def test_archive_symlinks_and_size_bombs_are_rejected():
    entry = ZipInfo("link.py")
    entry.create_system = 3
    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(ValueError, match="符号链接"):
        collect_sources([("unsafe.zip", archive([(entry, "target.py")]))])
    with pytest.raises(ValueError, match="1 MiB"):
        collect_sources([("huge.py", b"#" * (1024 * 1024 + 1))])
    with pytest.raises(ValueError, match="最多"):
        collect_sources([("many.zip", archive([(f"{i}.py", SAFE) for i in range(201)]))])


def test_import_requires_login(client):
    assert client.post("/api/projects/import", files={"files": ("a.py", SAFE)}).status_code == 401


def test_capacity_limit_preserves_import_for_later_start(admin, monkeypatch):
    runner = admin.app.state.runner
    monkeypatch.setattr(runner, "start", lambda project_id: (_ for _ in ()).throw(ValueError("已达到最大并发数")))
    response = admin.post("/api/projects/import", files={"files": ("a.py", SAFE)})
    assert response.status_code == 202
    assert response.json()["started"] is False
    assert admin.app.state.db.one("SELECT code_text FROM code_submissions WHERE project_id=?", (response.json()["project_id"],))["code_text"] == SAFE


def test_regular_user_can_import_and_other_users_cannot_read_code(admin):
    owner = {"username": "source_owner", "password": "source-owner-password"}
    other = {"username": "source_other", "password": "source-other-password"}
    for credentials in (owner, other):
        assert admin.post("/api/system/users", json=credentials).status_code == 201
    assert admin.post("/api/system/login", json=owner).status_code == 200
    imported = admin.post("/api/projects/import", files={"files": ("private.py", SAFE)})
    assert imported.status_code == 202
    project_id = imported.json()["project_id"]
    assert wait_done(admin, project_id)["project_status"] == "completed"
    submission_id = admin.get(f"/api/projects/{project_id}/submissions").json()[0]["id"]
    assert admin.post("/api/system/login", json=other).status_code == 200
    assert admin.get(f"/api/projects/{project_id}/submissions/{submission_id}").status_code == 403


def test_oversize_request_is_rejected_before_creating_project(admin):
    response = admin.post("/api/projects/import", content=b"x" * (21 * 1024 * 1024 + 1), headers={"Content-Type": "application/octet-stream"})
    assert response.status_code == 413
    assert admin.get("/api/projects").json() == []


def test_import_transaction_rolls_back_all_source_files(admin, monkeypatch):
    database = admin.app.state.db
    original = database.insert_on
    def fail(connection, table, **values):
        if table == "code_submissions" and values["filename"] == "b.py":
            raise RuntimeError("simulated storage failure")
        return original(connection, table, **values)
    monkeypatch.setattr(database, "insert_on", fail)
    with pytest.raises(RuntimeError, match="storage failure"):
        admin.post("/api/projects/import", files=[("files", ("a.py", SAFE)), ("files", ("b.py", SAFE))])
    assert admin.get("/api/projects").json() == []
    assert database.all("SELECT * FROM code_submissions") == []


def test_import_uses_configured_model_and_preserves_static_results(admin, monkeypatch):
    original = httpx.AsyncClient
    seen = []
    def respond(request):
        seen.append(json.loads(request.content))
        return httpx.Response(401)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(respond), **kwargs))
    config = admin.get("/api/system/llm/config").json()
    assert admin.put("/api/system/llm/config", json={**config, "enabled": True, "api_key": "test-import-key"}).status_code == 200
    response = admin.post("/api/projects/import", files={"files": ("review.py", UNSAFE)})
    assert response.status_code == 202, response.text
    project_id = response.json()["project_id"]
    assert wait_done(admin, project_id)["project_status"] == "completed"
    assert len(seen) == 1
    analysis = admin.get(f"/api/projects/{project_id}/submission-analyses").json()[0]
    assert analysis["llm_status"] == "failed"
    assert len(admin.get(f"/api/projects/{project_id}/vulnerabilities").json()) == 1
