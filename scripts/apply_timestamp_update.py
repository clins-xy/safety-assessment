"""Pause only this workspace's idle services, migrate timestamps, and restart them."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen

from dotenv import load_dotenv
import psutil
import pymysql


ROOT = Path(__file__).resolve().parents[1]


def assert_idle():
    load_dotenv(ROOT / ".env", override=False)
    connection = pymysql.connect(host=os.getenv("SAFETY_MYSQL_HOST", "127.0.0.1"),
        port=int(os.getenv("SAFETY_MYSQL_PORT", "3306")), user=os.getenv("SAFETY_MYSQL_USER", "root"),
        password=os.getenv("SAFETY_MYSQL_PASSWORD", ""), database=os.getenv("SAFETY_MYSQL_DATABASE", "safety"), connect_timeout=5)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM projects WHERE project_status='running' LIMIT 1")
            if cursor.fetchone():
                raise RuntimeError("仍有评估运行，取消维护，未停止服务")
    finally:
        connection.close()


def main():
    services = []
    for entry in psutil.net_connections(kind="tcp"):
        if entry.status != psutil.CONN_LISTEN or entry.laddr.port not in (8000, 8001):
            continue
        process = psutil.Process(entry.pid)
        cwd = Path(process.cwd()).resolve()
        command = process.cmdline()
        if not cwd.is_relative_to(ROOT) or process.name().lower() != "python.exe" or not any("safety_assessment" in argument for argument in command):
            raise RuntimeError("端口由其他应用占用，拒绝停止")
        if any(service["port"] == entry.laddr.port for service in services):
            continue
        services.append({"port": entry.laddr.port, "cwd": str(cwd), "process": process})
    assert_idle()
    if not services:
        services = [{"port": 8001, "cwd": str(ROOT), "process": None}]
    state = ROOT / "data" / "timestamp-maintenance-services.json"
    state.write_text(json.dumps([{key: value for key, value in service.items() if key != "process"} for service in services], indent=2), encoding="utf-8")
    stopped = []
    try:
        for service in services:
            process = service["process"]
            if process is not None:
                process.terminate()
                process.wait(timeout=15)
            stopped.append(service)
        subprocess.run([sys.executable, str(ROOT / "scripts" / "migrate_timestamps.py"), "--apply"], cwd=ROOT, check=True)
    finally:
        for service in stopped:
            logs = ROOT / "data"
            with (logs / f"service-{service['port']}-timestamps.stdout.log").open("ab") as output, (logs / f"service-{service['port']}-timestamps.stderr.log").open("ab") as errors:
                process = subprocess.Popen([sys.executable, "-m", "safety_assessment", "--host", "127.0.0.1", "--port", str(service["port"])],
                    cwd=service["cwd"], stdin=subprocess.DEVNULL, stdout=output, stderr=errors, close_fds=True,
                    creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
            for _ in range(40):
                try:
                    with urlopen(f"http://127.0.0.1:{service['port']}/api/system/status", timeout=1) as response:
                        status = json.load(response)
                    print(f"Restarted http://127.0.0.1:{service['port']}; backend={status['database']}; PID={process.pid}", flush=True)
                    break
                except OSError:
                    time.sleep(0.25)
            else:
                raise RuntimeError(f"{service['port']} 重启失败，请查看 data/service-{service['port']}-timestamps.stderr.log")


if __name__ == "__main__":
    main()
