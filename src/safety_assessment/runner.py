import asyncio
import html
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import psutil

from .analyzer import analyze
from .db import now
from .environment import Cancelled, Environment, remove_tree


STAGES = ["environment_scan", "code_analysis", "vulnerability_verify", "report_generate", "done"]
ROLES = {
    "general": "通用协调", "environment": "环境检查", "analyst": "代码分析",
    "verifier": "漏洞验证", "reporter": "报告整理", "operations": "运维辅助",
}


class EventBus:
    def __init__(self):
        self.clients = {}
        self.lock = threading.Lock()

    def subscribe(self, project_id):
        queue = asyncio.Queue(maxsize=256)
        entry = (asyncio.get_running_loop(), queue)
        with self.lock:
            self.clients.setdefault(project_id, []).append(entry)
        return entry

    def unsubscribe(self, project_id, entry):
        with self.lock:
            entries = self.clients.get(project_id, [])
            if entry in entries:
                entries.remove(entry)

    def publish(self, project_id, event_type, payload):
        event = {"type": event_type, "timestamp": now(), "data": {"project_id": project_id, **payload}}
        with self.lock:
            entries = list(self.clients.get(project_id, []))
        for loop, queue in entries:
            def deliver(queue=queue, event=event):
                if queue.full():
                    queue.get_nowait()
                queue.put_nowait(event)
            try:
                loop.call_soon_threadsafe(deliver)
            except RuntimeError:
                pass


class Runner:
    def __init__(self, db, bus):
        self.db = db
        self.bus = bus
        self.lock = threading.RLock()
        self.jobs = {}
        self.pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix="assessment")
        self.analysis_service = None
        db.execute("UPDATE projects SET project_status='failed', error_message='服务重启导致任务中断', finished_at=? WHERE project_status='running'", (now(),))
        db.execute("UPDATE runtime_stages SET stage_status='failed', error_message='服务重启', finished_at=? WHERE stage_status='running'", (now(),))
        db.execute("UPDATE worker_tasks SET task_status='failed', error_message='服务重启', finished_at=? WHERE task_status IN ('running','idle')", (now(),))

    def publish(self, project_id, kind, **payload):
        self.bus.publish(project_id, kind, payload)

    def log(self, project_id, message, level="info", stage_id=None, worker_id=None):
        record = dict(project_id=project_id, stage_id=stage_id, worker_task_id=worker_id, log_level=level, log_content=message, created_at=now())
        record["id"] = self.db.insert("runtime_logs", **record)
        directory = self.db.root / "runtime_logs" / str(project_id)
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "runtime.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.publish(project_id, "runtime_log", **{key: value for key, value in record.items() if key != "project_id"})

    def start(self, project_id):
        with self.lock:
            project = self.db.one("SELECT * FROM projects WHERE id=?", (project_id,))
            if project_id in self.jobs or project["project_status"] == "running":
                raise ValueError("任务已经在运行")
            if project["project_status"] != "created":
                raise ValueError("每个项目保留一次评估结果；重新评估请创建新项目")
            if project["source_type"] == "inline":
                submissions = self.db.all("SELECT id FROM code_submissions WHERE project_id=?", (project_id,))
                if not submissions:
                    raise ValueError("请先提交 Python 源码，再启动评估")
                if not project["source_path"].startswith("uploaded://") and self.db.one("SELECT code_submissions.id FROM code_submissions LEFT JOIN submission_analyses ON submission_analyses.submission_id=code_submissions.id WHERE code_submissions.project_id=? AND submission_analyses.id IS NULL", (project_id,)):
                    raise ValueError("代码分析尚未完成，请等待完成或重新分析后再启动评估")
            if len(self.jobs) >= self.db.config()["max_concurrency"]:
                raise ValueError("已达到最大并发数，请稍后启动")
            cancel = threading.Event()
            with self.db.connect() as connection:
                connection.execute("UPDATE projects SET project_status='running', started_at=?, updated_at=? WHERE id=?", (now(), now(), project_id))
                for stage in STAGES:
                    connection.execute("INSERT INTO runtime_stages (project_id,stage_name,stage_status) VALUES (?,?,?)", (project_id, stage, "idle"))
            self.jobs[project_id] = (cancel, None)
            future = self.pool.submit(self.run, project_id, cancel)
            self.jobs[project_id] = (cancel, future)
            self.publish(project_id, "project_status", project_status="running")

    def stop(self, project_id):
        with self.lock:
            job = self.jobs.get(project_id)
            if not job:
                raise ValueError("项目没有运行中的任务")
            job[0].set()
            future = job[1]
        if future:
            future.result(timeout=30)

    def shutdown(self):
        with self.lock:
            for cancel, _ in self.jobs.values():
                cancel.set()
        self.pool.shutdown(wait=True, cancel_futures=True)

    def task(self, project_id, stage_id, role, content, operation, environment):
        environment.check()
        worker_id = self.db.insert("worker_tasks", project_id=project_id, stage_id=stage_id, worker_role=role, task_content=content, task_status="idle")
        self.publish(project_id, "worker_status", worker_task_id=worker_id, worker_role=role, task_status="idle")
        self.db.execute("UPDATE worker_tasks SET task_status='running', started_at=? WHERE id=?", (now(), worker_id))
        self.publish(project_id, "worker_status", worker_task_id=worker_id, worker_role=role, task_status="running")
        self.log(project_id, f"{ROLES[role]}：{content}", stage_id=stage_id, worker_id=worker_id)
        try:
            result = operation()
            environment.check()
            summary = str(result)[:1500]
            self.db.execute("UPDATE worker_tasks SET task_status='success', result_summary=?, finished_at=? WHERE id=?", (summary, now(), worker_id))
            message = f"{ROLES[role]}完成：{summary}"
            self.db.insert("chat_messages", project_id=project_id, worker_role=role, message_type="result", message_text=message, created_at=now())
            self.publish(project_id, "chat_message", worker_role=role, message_text=message)
            self.publish(project_id, "worker_status", worker_task_id=worker_id, worker_role=role, task_status="success")
            return result
        except Exception as error:
            self.db.execute("UPDATE worker_tasks SET task_status='failed', error_message=?, finished_at=? WHERE id=?", (str(error), now(), worker_id))
            self.publish(project_id, "worker_status", worker_task_id=worker_id, worker_role=role, task_status="failed")
            raise

    def resources(self, project_id, environment):
        process = psutil.Process()
        while not environment.cancel.is_set():
            record = dict(cpu_usage=process.cpu_percent(), memory_usage=round(process.memory_info().rss / 1024**2, 2), token_count=0, recorded_at=now())
            self.db.insert("resource_usages", project_id=project_id, **record)
            self.publish(project_id, "resource_usage", **record)
            if environment.cancel.wait(0.75):
                break

    def run(self, project_id, cancel):
        project = self.db.one("SELECT * FROM projects WHERE id=?", (project_id,))
        environment = None
        monitor_cancel = threading.Event()
        resource_environment = type("Monitor", (), {"cancel": monitor_cancel})()
        monitor = threading.Thread(target=self.resources, args=(project_id, resource_environment), daemon=True)
        monitor.start()
        current_stage = None
        try:
            environment = Environment(self.db, project, cancel, time.monotonic() + self.db.config()["default_timeout"])
            source = None
            sources = {}
            for stage_name in STAGES:
                environment.check()
                stage = self.db.one("SELECT * FROM runtime_stages WHERE project_id=? AND stage_name=?", (project_id, stage_name))
                current_stage = stage["id"]
                self.db.execute("UPDATE runtime_stages SET stage_status='running', started_at=? WHERE id=?", (now(), current_stage))
                self.publish(project_id, "stage_status", stage_name=stage_name, stage_status="running")
                if stage_name == "environment_scan":
                    self.task(project_id, current_stage, "general", "确认项目范围与任务说明", lambda: project["task_content"] or "仅对授权源码进行静态安全评估", environment)
                    source = self.task(project_id, current_stage, "environment", "准备独立环境并检查源码只读接入", environment.prepare, environment)
                    self.task(project_id, current_stage, "operations", "记录环境模式与执行限制", lambda: f"环境 {project['environment_id']}；{project['environment_type']}；静态模式不执行目标代码，Docker 模式禁网、只读、限额。资源为后端进程值；token 用量当前未统计。", environment)
                elif stage_name == "code_analysis":
                    def scan():
                        count = 0
                        skipped = 0
                        if project["source_type"] == "inline":
                            submissions = self.db.all("SELECT * FROM code_submissions WHERE project_id=? ORDER BY id", (project_id,))
                            for submission in submissions:
                                environment.check()
                                filename = submission["filename"]
                                sources[filename] = submission["code_text"]
                                if not self.db.one("SELECT id FROM submission_analyses WHERE submission_id=?", (submission["id"],)):
                                    if self.analysis_service is None:
                                        raise ValueError("分析服务未就绪")
                                    self.log(project_id, f"正在分析 {count + 1}/{len(submissions)}：{filename}", stage_id=current_stage)
                                    async def review_submission():
                                        task = asyncio.create_task(self.analysis_service.analyze_submission(project_id, submission["id"], filename, submission["code_text"]))
                                        try:
                                            while not task.done():
                                                environment.check()
                                                await asyncio.wait({task}, timeout=0.2)
                                            return task.result()
                                        finally:
                                            if not task.done():
                                                task.cancel()
                                            await asyncio.gather(task, return_exceptions=True)
                                    result = asyncio.run(review_submission())
                                    self.log(project_id, f"分析 {filename}：规则 {len(result['static'])} 条；LLM {result['llm_status']}", stage_id=current_stage)
                                count += 1
                                self.publish(project_id, "import_progress", files_done=count, files_total=len(submissions), filename=filename)
                            return f"已分析 {count} 个上传的 Python 文件，源码及结果均已保存。"
                        for path in environment.files(source):
                            environment.check()
                            relative = path.relative_to(source).as_posix()
                            text = path.read_bytes()[:self.db.config()["max_file_bytes"] + 1]
                            if len(text) > self.db.config()["max_file_bytes"]:
                                continue
                            try:
                                text = text.decode("utf-8-sig")
                                findings = analyze(text, relative)
                            except (UnicodeError, SyntaxError, RecursionError) as error:
                                skipped += 1
                                self.log(project_id, f"跳过 {relative}：{error}", "warning", current_stage)
                                continue
                            sources[relative] = text
                            count += 1
                            self.log(project_id, f"分析 {relative}：{len(findings)} 个危险信号", stage_id=current_stage)
                            for finding in findings:
                                environment.check()
                                vuln_id = self.db.insert("vulnerabilities", project_id=project_id, vuln_code=f"V-{project_id}-{count:04d}-{finding['line_number']}", created_at=now(), **finding)
                                self.publish(project_id, "vulnerability_found", vuln_id=vuln_id, vuln_title=finding["vuln_title"], risk_level=finding["risk_level"])
                        return f"已分析 {count} 个 Python 文件，跳过 {skipped} 个不可解析文件；不支持的语言不代表安全。"
                    self.task(project_id, current_stage, "analyst", "遍历、读取源码并执行 AST 输入到危险调用的数据流规则", scan, environment)
                elif stage_name == "vulnerability_verify":
                    def verify():
                        rows = self.db.all("SELECT * FROM vulnerabilities WHERE project_id=?", (project_id,))
                        for row in rows:
                            environment.check()
                            if row["rule_id"].startswith("LLM:") or row["file_path"] not in sources:
                                self.db.execute("UPDATE vulnerabilities SET verify_status='needs_review' WHERE id=?", (row["id"],))
                                continue
                            reviewed_source = sources[row["file_path"]]
                            if row["vuln_code"].startswith("S-"):
                                submission_id = int(row["vuln_code"].split("-", 2)[1])
                                saved = self.db.one("SELECT code_text FROM code_submissions WHERE id=? AND project_id=?", (submission_id, project_id))
                                if saved:
                                    reviewed_source = saved["code_text"]
                            matches = analyze(reviewed_source, row["file_path"])
                            confirmed = any(item["rule_id"] == row["rule_id"] and item["line_number"] == row["line_number"] for item in matches)
                            self.db.execute("UPDATE vulnerabilities SET verify_status=? WHERE id=?", ("static_confirmed" if confirmed else "needs_review", row["id"]))
                            path_id = self.db.insert("attack_paths", project_id=project_id, path_code=f"AP-{row['id']}", path_title=row["vuln_title"] + "（候选路径）", path_summary="输入入口 → 污染传播 → 危险调用；未证明跨漏洞可串联，未动态利用。", final_impact_text=row["impact_text"], created_at=now())
                            self.db.insert("attack_path_items", path_id=path_id, vuln_id=row["id"], step_order=1, step_text=f"人工确认入口可控后审查 {row['file_path']}:{row['line_number']}，规则 {row['rule_id']}")
                        return f"复核 {len(rows)} 条静态信号；static_confirmed 仅确认规则命中，不表示真实攻击已成功。"
                    self.task(project_id, current_stage, "verifier", "独立重新解析源码，核对规则、位置并整理候选路径", verify, environment)
                elif stage_name == "report_generate":
                    self.task(project_id, current_stage, "reporter", "生成风险结论、证据、修复建议与评估边界", lambda: self.report(project, environment), environment)
                environment.check()
                self.db.execute("UPDATE runtime_stages SET stage_status='success', finished_at=? WHERE id=?", (now(), current_stage))
                self.publish(project_id, "stage_status", stage_name=stage_name, stage_status="success")
            self.finish(project_id, "completed")
        except Exception as error:
            status = "stopped" if isinstance(error, Cancelled) else "failed"
            if current_stage:
                self.db.execute("UPDATE runtime_stages SET stage_status='failed', finished_at=?, error_message=? WHERE id=? AND stage_status='running'", (now(), str(error), current_stage))
                stage = self.db.one("SELECT stage_name FROM runtime_stages WHERE id=?", (current_stage,))
                self.publish(project_id, "stage_status", stage_name=stage["stage_name"], stage_status="failed")
            self.log(project_id, str(error), "warning" if status == "stopped" else "error", current_stage)
            self.finish(project_id, status, str(error))
        finally:
            monitor_cancel.set()
            monitor.join(timeout=3)
            if environment and not environment.destroy():
                self.log(project_id, "容器自动清理失败，请管理员检查并清理 " + environment.container, "error")
            with self.lock:
                self.jobs.pop(project_id, None)

    def finish(self, project_id, status, error=None):
        with self.lock:
            job = self.jobs.get(project_id)
            if status == "completed" and job and job[0].is_set():
                status, error = "stopped", "任务已停止；保留已保存结果"
            self.db.execute("UPDATE projects SET project_status=?, finished_at=?, updated_at=?, error_message=? WHERE id=?", (status, now(), now(), error, project_id))
            self.publish(project_id, "project_status", project_status=status)

    def report(self, project, environment):
        project_id = project["id"]
        vulnerabilities = self.db.all("SELECT * FROM vulnerabilities WHERE project_id=?", (project_id,))
        paths = self.db.all("SELECT * FROM attack_paths WHERE project_id=?", (project_id,))
        tasks = self.db.all("SELECT worker_role, task_status, result_summary FROM worker_tasks WHERE project_id=?", (project_id,))
        sections = [f"# {project['project_name']} · 安全评估报告", "## 项目概述", f"源码：{project['source_path']}\n\n任务：{project['task_content']}\n\n环境：{project['environment_type']} / {project['environment_id']}", "## 执行过程", *[f"- {ROLES[task['worker_role']]}：{task['task_status']}；{task['result_summary'] or '报告生成中'}" for task in tasks], "## 漏洞汇总", f"发现 {len(vulnerabilities)} 个候选危险信号。"]
        reviews = self.db.all("SELECT filename, status, summary FROM llm_analyses WHERE project_id=? ORDER BY id", (project_id,))
        if reviews:
            sections += ["## 大语言模型复核", *[f"- {row['filename']}：{row['status']}；{row['summary']}" for row in reviews]]
        for row in vulnerabilities:
            sections += [f"### {row['vuln_code']} {row['vuln_title']}", f"风险：{row['risk_level']}；验证：{row['verify_status']}；位置：{row['file_path']}:{row['line_number']}", row["impact_text"], "触发条件：" + row["condition_text"], "证据：\n```python\n" + row["evidence_text"] + "\n```", "复现步骤：\n" + row["reproduce_steps_text"], "验证方式：" + row["verify_code_text"], "修复建议：" + row["remediation_text"]]
        sections += ["## 攻击路径", *[f"- {row['path_code']}：{row['path_title']}；{row['path_summary']} 最终影响：{row['final_impact_text']}" for row in paths], "## 风险结论", "存在需要人工复核的危险信号，建议按风险等级检查和修复。" if vulnerabilities else "当前规则未发现危险信号；不等于项目不存在漏洞。", "## 修复建议", "采用参数化 SQL、无 Shell 参数列表，避免动态执行用户输入；修复后创建新评估项目复测。", "## 评估边界", "本系统使用 Python AST 静态规则，提交代码可选大语言模型复核，不安装依赖、不执行目标项目。静态规则仅覆盖 SQL、Shell、动态代码注入的部分模式；不具备完整跨函数/跨文件污点分析。函数参数按潜在外部输入处理，存在误报与漏报。static_confirmed 是重复静态核验，不是动态漏洞证实。LLM 建议始终标为 needs_review。攻击路径是候选单漏洞路径，不虚构漏洞串联。", "资源数据为后端进程 CPU 与 RSS（MiB），不是容器级统计；token 字段当前未统计模型用量，0 不表示未调用模型。源码扫描受文件数、大小、编码、超时限制。静态演示模式仅逻辑隔离，不是 OS 沙箱；真正的容器环境请选 Docker。"]
        markdown = "\n\n".join(sections)
        report_html = "<!doctype html><html lang='zh-CN'><meta charset='utf-8'><title>安全评估报告</title><body><pre style='white-space:pre-wrap;font:16px/1.8 system-ui'>" + html.escape(markdown) + "</pre></body></html>"
        directory = self.db.root / "reports" / str(project_id)
        directory.mkdir(parents=True, exist_ok=True)
        environment.check()
        path = directory / "report.md"
        path.write_text(markdown, encoding="utf-8")
        (directory / "report.html").write_text(report_html, encoding="utf-8")
        report_id = self.db.insert("reports", project_id=project_id, report_markdown=markdown, report_html=report_html, report_file_path=str(path), created_at=now())
        self.publish(project_id, "report_ready", report_id=report_id)
        return f"报告 #{report_id} 已生成，包含 {len(vulnerabilities)} 条信号与 {len(paths)} 条候选路径"

    def delete(self, project_id):
        with self.lock:
            if project_id in self.jobs:
                raise ValueError("请先停止任务，再删除项目")
            for name in ("runtime_logs", "reports", "workspace"):
                remove_tree(self.db.root / name / str(project_id), self.db.root / name)
            self.db.execute("DELETE FROM projects WHERE id=?", (project_id,))
