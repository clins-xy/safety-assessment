"""Back up and migrate only business timestamp values; never change table definitions."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from dotenv import load_dotenv
import pymysql

from safety_assessment.timestamps import TIME_FORMAT, format_timestamp


ROOT = Path(__file__).resolve().parents[1]
TIME_COLUMNS = {"created_at", "updated_at", "started_at", "finished_at", "recorded_at"}


def fingerprint(rows, columns):
    content = [{key: value for key, value in row.items() if key not in columns} for row in rows]
    encoded = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def plan_changes(rows, columns):
    records = []
    for row in rows:
        before = {column: row[column] for column in columns}
        try:
            after = {column: format_timestamp(value) if value is not None else None for column, value in before.items()}
        except (ValueError, TypeError) as error:
            raise ValueError(f"记录 #{row['id']} 存在无法转换的时间，整个迁移已取消") from error
        records.append({"id": row["id"], "before": before, "after": after})
    return records


def apply_records(connection, tables, direction="after"):
    with connection.cursor() as cursor:
        for table in tables:
            columns = table["columns"]
            assignments = ",".join(f"`{column}`=%s" for column in columns)
            for record in table["records"]:
                if record["before"] == record["after"]:
                    continue
                values = record[direction]
                cursor.execute(f"UPDATE `{table['name']}` SET {assignments} WHERE id=%s",
                               tuple(values[column] for column in columns) + (record["id"],))


def snapshot(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION")
        schema = cursor.fetchall()
        cursor.execute("SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME")
        engines = {row["TABLE_NAME"]: row["ENGINE"] for row in cursor.fetchall()}
        targets = {}
        for column in schema:
            if column["COLUMN_NAME"] in TIME_COLUMNS:
                if not column["COLUMN_TYPE"].startswith(("varchar", "text")):
                    raise ValueError("时间字段不是文本，拒绝自动改动结构")
                targets.setdefault(column["TABLE_NAME"], []).append(column["COLUMN_NAME"])
        tables = []
        for name, columns in targets.items():
            if engines.get(name) != "InnoDB":
                raise ValueError("目标表不支持事务，已取消迁移")
            cursor.execute(f"SELECT * FROM `{name}` ORDER BY id FOR UPDATE")
            rows = cursor.fetchall()
            tables.append({"name": name, "columns": columns, "row_count": len(rows),
                           "non_time_sha256": fingerprint(rows, columns), "records": plan_changes(rows, columns)})
        untouched = []
        for name in engines.keys() - targets.keys():
            cursor.execute(f"SHOW KEYS FROM `{name}` WHERE Key_name='PRIMARY'")
            keys = [row["Column_name"] for row in sorted(cursor.fetchall(), key=lambda row: row["Seq_in_index"])]
            if not keys:
                raise ValueError(f"{name} 没有主键，无法稳定校验")
            ordering = ",".join(f"`{key}`" for key in keys)
            cursor.execute(f"SELECT * FROM `{name}` ORDER BY {ordering}")
            rows = cursor.fetchall()
            untouched.append({"name": name, "ordering": ordering, "row_count": len(rows), "sha256": fingerprint(rows, [])})
        return schema, tables, untouched


def verify_untouched(connection, tables):
    with connection.cursor() as cursor:
        for table in tables:
            cursor.execute(f"SELECT * FROM `{table['name']}` ORDER BY {table['ordering']}")
            rows = cursor.fetchall()
            if len(rows) != table["row_count"] or fingerprint(rows, []) != table["sha256"]:
                raise ValueError(f"{table['name']} 数据发生变化，已取消迁移")


def verify(connection, tables, direction="after"):
    with connection.cursor() as cursor:
        for table in tables:
            cursor.execute(f"SELECT * FROM `{table['name']}` ORDER BY id")
            rows = cursor.fetchall()
            if len(rows) != table["row_count"] or fingerprint(rows, table["columns"]) != table["non_time_sha256"]:
                raise ValueError(f"{table['name']} 非时间数据发生变化，迁移已回滚")
            expected = {record["id"]: record[direction] for record in table["records"]}
            if any({column: row[column] for column in table["columns"]} != expected.get(row["id"]) for row in rows):
                raise ValueError(f"{table['name']} 时间校验失败，迁移已回滚")


def main():
    parser = argparse.ArgumentParser(description="统一业务时间为北京时间 YYYY/MM/DD/HH.mm，须先停止项目服务")
    parser.add_argument("--apply", action="store_true", help="备份后执行迁移；默认只检查")
    parser.add_argument("--restore", type=Path, help="从本脚本产生的备份恢复时间值；必须先停止服务")
    args = parser.parse_args()
    if args.apply and args.restore:
        parser.error("--apply 与 --restore 不能同时使用")
    load_dotenv(ROOT / ".env", override=False)
    connection = pymysql.connect(host=os.getenv("SAFETY_MYSQL_HOST", "127.0.0.1"),
        port=int(os.getenv("SAFETY_MYSQL_PORT", "3306")), user=os.getenv("SAFETY_MYSQL_USER", "root"),
        password=os.getenv("SAFETY_MYSQL_PASSWORD", ""), database=os.getenv("SAFETY_MYSQL_DATABASE", "safety"),
        charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor, connect_timeout=5, read_timeout=30, write_timeout=30)
    backup_path = None
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT DATABASE() AS name")
            database_name = cursor.fetchone()["name"]
            cursor.execute("SELECT id FROM projects WHERE project_status='running' LIMIT 1")
            if cursor.fetchone():
                raise ValueError("仍有运行中的评估，请等待完成并停止服务后迁移")
        schema, tables, untouched = snapshot(connection)
        changed_cells = sum(record["before"][column] != record["after"][column]
                            for table in tables for record in table["records"] for column in table["columns"])
        if args.restore:
            backup = json.loads(args.restore.read_text(encoding="utf-8"))
            if backup["database"] != database_name or backup["schema"] != schema:
                raise ValueError("备份的数据库或表结构不匹配，已取消恢复")
            verify(connection, backup["tables"], "after")
            apply_records(connection, backup["tables"], "before")
            verify(connection, backup["tables"], "before")
            verify_untouched(connection, untouched)
            connection.commit()
            print("时间备份已恢复；表结构和其他字段未改动")
            return
        print(json.dumps({"database": database_name, "tables": len(tables), "rows": sum(table["row_count"] for table in tables),
                          "changed_time_values": changed_cells, "timezone": "Asia/Shanghai (UTC+08:00)", "format": TIME_FORMAT}, ensure_ascii=False))
        if not args.apply or not changed_cells:
            connection.rollback()
            return
        directory = ROOT / "data" / "backups"
        directory.mkdir(parents=True, exist_ok=True)
        backup_path = directory / ("timestamps-before-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        backup = {"version": 1, "database": database_name, "schema": schema, "tables": tables, "untouched_tables": untouched}
        with backup_path.open("x", encoding="utf-8") as stream:
            json.dump(backup, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        apply_records(connection, tables)
        verify(connection, tables)
        verify_untouched(connection, untouched)
        with connection.cursor() as cursor:
            cursor.execute("SELECT TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION")
            if cursor.fetchall() != schema:
                raise ValueError("表结构发生变化，已回滚")
        connection.commit()
        print(f"迁移完成；已核对全部时间值、行数及非时间数据。备份：{backup_path}")
    except Exception:
        connection.rollback()
        if backup_path:
            print(f"迁移未提交；原始时间备份保留于 {backup_path}")
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    main()
