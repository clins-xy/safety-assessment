import threading
import time
from pathlib import Path

import pytest

from safety_assessment.db import Database
from safety_assessment.environment import Environment, checked_repository


def test_docker_is_restricted_and_source_readonly(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFETY_DB_BACKEND", "sqlite")
    database = Database(tmp_path / "data")
    source = Path(__file__).parents[1] / "src" / "safety_assessment" / "examples" / "safe"
    project = {"id": 1, "source_type": "local", "source_path": str(source), "environment_type": "docker", "environment_id": "safety-test"}
    environment = Environment(database, project, threading.Event(), time.monotonic() + 30)
    commands = []

    def command(arguments, **kwargs):
        commands.append(arguments)
        return "ok"

    monkeypatch.setattr(environment, "command", command)
    assert environment.prepare() == source
    create = commands[0]
    assert create[:2] == ["docker", "create"]
    for flag, value in (("--network", "none"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"), ("--user", "65534:65534"), ("--memory", "256m"), ("--cpus", "0.5")):
        assert create[create.index(flag) + 1] == value
    assert "--read-only" in create
    assert create[create.index("--mount") + 1].endswith("target=/source,readonly")
    assert commands[1] == ["docker", "start", "safety-test"]
    assert commands[2][:3] == ["docker", "exec", "safety-test"]


@pytest.mark.parametrize("url", ["file:///tmp/repo", "ssh://example.com/repo", "https://user:password@example.com/repo", "https://example.com:3306/repo", "https://example.com/repo?token=secret"])
def test_disallowed_repository_urls(url):
    with pytest.raises(ValueError):
        checked_repository(url)


def test_repository_blocks_private_dns(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(ValueError):
        checked_repository("https://example.com/repo")
