import argparse
import getpass
import time

import httpx


def main():
    parser = argparse.ArgumentParser(description="正反案例端到端演示（先启动服务并初始化管理员）")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="admin")
    args = parser.parse_args()
    with httpx.Client(base_url=args.url, timeout=40) as client:
        login = client.post("/api/system/login", json={"username": args.username, "password": getpass.getpass("登录密码：")})
        login.raise_for_status()
        examples = client.get("/api/examples").json()
        for example in examples:
            response = client.post("/api/projects", json={"project_name": example["name"], "source_type": "local", "source_path": example["path"], "task_content": "正反案例完整演示", "environment_type": "static"})
            response.raise_for_status()
            project = response.json()
            prefix = f"/api/projects/{project['id']}"
            client.post(prefix + "/start").raise_for_status()
            deadline = time.monotonic() + 360
            while time.monotonic() < deadline:
                response = client.get(prefix)
                response.raise_for_status()
                project = response.json()
                if project["project_status"] != "running":
                    break
                time.sleep(0.3)
            if project["project_status"] != "completed":
                raise RuntimeError(project)
            findings = client.get(prefix + "/vulnerabilities").json()
            if len(findings) != example["expected_findings"]:
                raise AssertionError(f"信号数量不符合预期：{len(findings)}")
            print(f"{example['name']}：{len(findings)} 条危险信号，预期一致。")
            print(f"项目：{args.url}/#project/{project['id']}/report")
            print(f"报告：{args.url}{prefix}/report/download")


if __name__ == "__main__":
    main()
