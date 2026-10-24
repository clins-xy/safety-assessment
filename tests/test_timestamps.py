from datetime import datetime
import re
import asyncio
import sqlite3
import time

import pytest

from safety_assessment.db import now
from safety_assessment.timestamps import TIME_FORMAT, BEIJING_TIME, format_timestamp
from safety_assessment.runner import EventBus
from scripts.migrate_timestamps import apply_records, fingerprint, plan_changes
from tests.test_system import wait_done


@pytest.mark.parametrize("original,expected", [
    ("2026-10-23T02:11:59.999+00:00", "2026/10/23/10.11"),
    ("2026-10-22T18:11:00Z", "2026/10/23/02.11"),
    ("2026-12-31T18:11:00+00:00", "2027/01/01/02.11"),
    ("2026-10-23T10:11:00+08:00", "2026/10/23/10.11"),
    ("2026-10-23 02:11:00", "2026/10/23/10.11"),
    ("2026/10/23/10.11", "2026/10/23/10.11"),
])
def test_timestamp_conversion_and_idempotence(original, expected):
    assert format_timestamp(original) == expected
    assert format_timestamp(expected) == expected


@pytest.mark.parametrize("value", ["not-a-date", "2026/02/30/10.11", "2026/10/23/25.11"])
def test_invalid_times_fail_instead_of_being_overwritten(value):
    with pytest.raises(ValueError):
        format_timestamp(value)


def test_now_uses_beijing_and_fixed_width_minute_format():
    lower = datetime.now(BEIJING_TIME).strftime(TIME_FORMAT)
    value = now()
    upper = datetime.now(BEIJING_TIME).strftime(TIME_FORMAT)
    assert lower <= value <= upper
    assert re.fullmatch(r"\d{4}/\d{2}/\d{2}/\d{2}\.\d{2}", value)
    assert len(value) == 16


def test_compact_dates_sort_chronologically():
    times = ["2027-01-01T00:00:00Z", "2026-10-23T01:01:00Z", "2026-09-30T23:59:00Z"]
    assert sorted(map(format_timestamp, times)) == list(map(format_timestamp, sorted(times)))


def test_migration_only_changes_time_cells_and_preserves_nulls():
    rows = [{"id": 1, "created_at": "2026-10-23T02:11:30+00:00", "finished_at": None, "code_text": "2026-10-23T02:11:30+00:00"}]
    columns = ["created_at", "finished_at"]
    records = plan_changes(rows, columns)
    assert records[0]["after"] == {"created_at": "2026/10/23/10.11", "finished_at": None}
    converted = [{**rows[0], **records[0]["after"]}]
    assert fingerprint(rows, columns) == fingerprint(converted, columns)
    assert rows[0]["created_at"].endswith("+00:00")
    assert plan_changes(converted, columns)[0]["before"] == plan_changes(converted, columns)[0]["after"]


def test_migration_rejects_invalid_value_without_partial_plan():
    rows = [{"id": 1, "created_at": "2026-10-23T02:11:30Z"}, {"id": 2, "created_at": "broken"}]
    with pytest.raises(ValueError, match="#2"):
        plan_changes(rows, ["created_at"])
    assert rows[0]["created_at"] == "2026-10-23T02:11:30Z"


def test_migration_can_apply_and_restore_original_precision():
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, created_at TEXT, finished_at TEXT)")
    original = "2026-10-23T02:11:30.123+00:00"
    connection.execute("INSERT INTO records VALUES (1, ?, NULL)", (original,))
    connection.commit()
    class Cursor:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def execute(self, sql, values):
            return connection.execute(sql.replace("%s", "?"), values)
    class Adapter:
        def cursor(self):
            return Cursor()
    tables = [{"name": "records", "columns": ["created_at", "finished_at"], "records": plan_changes([{"id": 1, "created_at": original, "finished_at": None}], ["created_at", "finished_at"])}]
    apply_records(Adapter(), tables)
    assert connection.execute("SELECT created_at,finished_at FROM records").fetchone() == ("2026/10/23/10.11", None)
    apply_records(Adapter(), tables, "before")
    assert connection.execute("SELECT created_at,finished_at FROM records").fetchone() == (original, None)
    connection.rollback()
    connection.close()


def test_event_timestamps_use_same_format():
    async def check():
        bus = EventBus()
        subscription = bus.subscribe(1)
        bus.publish(1, "test", {})
        event = await asyncio.wait_for(subscription[1].get(), timeout=1)
        assert re.fullmatch(r"\d{4}/\d{2}/\d{2}/\d{2}\.\d{2}", event["timestamp"])
        bus.unsubscribe(1, subscription)
    asyncio.run(check())


def test_new_pipeline_dates_sessions_and_log_files(admin):
    response = admin.post("/api/projects/import", files={"files": ("times.py", "import os\ndef run(value):\n    os.system(value)\n")})
    assert response.status_code == 202, response.text
    project_id = response.json()["project_id"]
    assert wait_done(admin, project_id)["project_status"] == "completed"
    database = admin.app.state.db
    table_names = [row["name"] for row in database.all("SELECT name FROM sqlite_master WHERE type='table'")]
    values = 0
    for table in table_names:
        for row in database.all(f'SELECT * FROM "{table}"'):
            for column, value in row.items():
                if column in ("created_at", "updated_at", "started_at", "finished_at", "recorded_at") and value is not None:
                    assert re.fullmatch(r"\d{4}/\d{2}/\d{2}/\d{2}\.\d{2}", value), (table, column, value)
                    values += 1
    assert values > 25
    session = database.one("SELECT expires_at FROM sessions LIMIT 1")
    assert isinstance(session["expires_at"], float)
    assert session["expires_at"] > time.time()
    assert admin.get("/api/system/me").status_code == 200
    database.execute("UPDATE sessions SET expires_at=?", (time.time() - 1,))
    assert admin.get("/api/system/me").status_code == 401
    import json
    for line in (database.root / "runtime_logs" / str(project_id) / "runtime.jsonl").read_text(encoding="utf-8").splitlines():
        assert format_timestamp(json.loads(line)["created_at"]) == json.loads(line)["created_at"]
