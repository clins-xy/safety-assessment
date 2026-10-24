import json
import asyncio
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .timestamps import now


DEFAULT_CONFIG = {
    "default_timeout": 300, "max_concurrency": 2, "retention_days": 30,
    "docker_image": "python:3.12-alpine", "allow_git": True,
    "max_files": 2000, "max_file_bytes": 1048576,
    "llm_enabled": False, "llm_provider": "openai_compatible", "llm_base_url": "https://api.openai.com/v1",
    "llm_api_key": "", "llm_model": "gpt-4o-mini", "llm_timeout_seconds": 45,
    "llm_max_code_chars": 12000,
    "llm_system_prompt": "你是代码安全审查助手。只分析输入源码，返回严格 JSON 对象；不要执行代码，不要编造证据。",
}


class Database:
    def __init__(self, root: Path | None = None):
        self.root = (root or Path(os.environ.get("SAFETY_DATA_DIR", "data"))).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "assessment.db"
        self.backend = os.environ.get("SAFETY_DB_BACKEND", "mysql")
        if self.backend not in ("mysql", "sqlite"):
            raise ValueError("SAFETY_DB_BACKEND must be mysql or sqlite")
        with self.connect() as connection:
            if self.backend == "sqlite":
                connection.execute("PRAGMA journal_mode=WAL")
                connection.executescript(Path(__file__).with_name("schema.sql").read_text(encoding="utf-8"))
            else:
                schema = Path(__file__).with_name("schema.mysql.sql").read_text(encoding="utf-8")
                required = set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", schema))
                existing = {next(iter(row.values())) for row in connection.execute("SHOW TABLES").fetchall()}
                missing = sorted(required - existing)
                if missing:
                    raise ValueError("MySQL 缺少所需表：" + ", ".join(missing) + "；程序不会自动修改表结构，请核对数据库。")
            for key, value in DEFAULT_CONFIG.items():
                connection.execute("INSERT OR IGNORE INTO system_config VALUES (?, ?)", (key, json.dumps(value)))

    @contextmanager
    def connect(self):
        if self.backend == "mysql":
            import pymysql

            raw = pymysql.connect(
                host=os.environ.get("SAFETY_MYSQL_HOST", "127.0.0.1"),
                port=int(os.environ.get("SAFETY_MYSQL_PORT", "3306")),
                user=os.environ.get("SAFETY_MYSQL_USER", "root"),
                password=os.environ.get("SAFETY_MYSQL_PASSWORD", ""),
                database=os.environ.get("SAFETY_MYSQL_DATABASE", "safety"),
                charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=5, read_timeout=20, write_timeout=20,
            )
            connection = MySQLConnection(raw)
        else:
            connection = sqlite3.connect(self.path, timeout=20)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def all(self, sql: str, params=()) -> list[dict]:
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, params).fetchall()]

    def one(self, sql: str, params=()) -> dict | None:
        rows = self.all(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params=()) -> int:
        with self.connect() as connection:
            return connection.execute(sql, params).lastrowid

    def insert(self, table: str, **values) -> int:
        with self.connect() as connection:
            return self.insert_on(connection, table, **values)

    @staticmethod
    def insert_on(connection, table: str, **values) -> int:
        columns = ", ".join(values)
        placeholders = ", ".join("?" for _ in values)
        return connection.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(values.values())).lastrowid

    def config(self) -> dict:
        return {row["key"]: json.loads(row["value"]) for row in self.all("SELECT * FROM system_config")}

    async def aall(self, sql: str, params=()) -> list[dict]:
        return await asyncio.to_thread(self.all, sql, params)

    async def aone(self, sql: str, params=()) -> dict | None:
        return await asyncio.to_thread(self.one, sql, params)

    async def aexecute(self, sql: str, params=()) -> int:
        return await asyncio.to_thread(self.execute, sql, params)

    async def ainsert(self, table: str, **values) -> int:
        return await asyncio.to_thread(self.insert, table, **values)

    async def aconfig(self) -> dict:
        return await asyncio.to_thread(self.config)

    def audit(self, user_id: int | None, action: str, detail: str):
        self.insert("audit_logs", user_id=user_id, action=action, detail=detail, created_at=now())


class MySQLConnection:
    def __init__(self, raw):
        self.raw = raw

    def execute(self, sql, params=()):
        sql = sql.replace("INSERT OR IGNORE", "INSERT IGNORE").replace("?", "%s")
        cursor = self.raw.cursor()
        cursor.execute(sql, params)
        return cursor

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()
