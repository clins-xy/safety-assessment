import pytest
from fastapi.testclient import TestClient

from safety_assessment.app import create_app
from safety_assessment.llm_settings import ENV_FIELDS


@pytest.fixture(autouse=True)
def isolate_model_environment(monkeypatch):
    # Tests must never send real code to a provider configured in the developer's .env.
    for variable in ENV_FIELDS.values():
        monkeypatch.setenv(variable, "")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFETY_DB_BACKEND", "sqlite")
    with TestClient(create_app(tmp_path / "data")) as client:
        yield client


@pytest.fixture
def admin(client):
    credentials = {"username": "test_admin", "password": "test-password-123"}
    assert client.post("/api/system/init", json=credentials).status_code == 201
    assert client.post("/api/system/login", json=credentials).status_code == 200
    return client
