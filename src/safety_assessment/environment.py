import ipaddress
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from .application.analysis.imports import source_filename


EXCLUDED = {".git", ".venv", "venv", "node_modules", "__pycache__", ".idea", ".agents", ".codex", ".aws", "data"}


class Cancelled(Exception):
    pass


def checked_local_path(value: str, data_root: Path) -> Path:
    path = Path(value).expanduser().resolve()
    roots = [Path(item).resolve() for item in os.environ.get("SAFETY_SOURCE_ROOTS", str(Path.cwd())).split(os.pathsep) if item]
    if not path.is_dir() or not any(path.is_relative_to(root) for root in roots):
        raise ValueError("源码必须是 SAFETY_SOURCE_ROOTS 允许范围内的目录")
    if path == data_root or path.is_relative_to(data_root) or any(part in EXCLUDED for part in path.parts):
        raise ValueError("不能接入系统数据、凭据或依赖目录")
    if "," in str(path):
        raise ValueError("源码路径不能含逗号")
    return path


def checked_repository(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("仅允许不含凭据的公网 HTTPS 仓库地址")
    if parsed.query or parsed.fragment:
        raise ValueError("仓库地址不能包含查询参数或片段")
    addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(address[4][0]).is_global for address in addresses):
        raise ValueError("不允许内网、回环或保留地址的仓库")
    return value


class Environment:
    def __init__(self, db, project: dict, cancel, deadline: float):
        self.db = db
        self.project = project
        self.cancel = cancel
        self.deadline = deadline
        self.work = db.root / "workspace" / str(project["id"])
        self.work.mkdir(parents=True, exist_ok=True)
        self.container = project["environment_id"]
        self.docker_started = False

    def check(self):
        if self.cancel.is_set():
            raise Cancelled("任务已停止")
        if time.monotonic() > self.deadline:
            raise TimeoutError("超过任务总超时时间")

    def command(self, arguments: list[str], *, env=None, limit=30) -> str:
        self.check()
        output_path = self.work / "command-output.txt"
        with output_path.open("wb") as output:
            process = subprocess.Popen(arguments, stdout=output, stderr=subprocess.STDOUT, env=env, shell=False)
            started = time.monotonic()
            try:
                while process.poll() is None:
                    self.check()
                    if time.monotonic() - started > limit or output_path.stat().st_size > 2_000_000:
                        raise TimeoutError("受控命令超时或输出过大")
                    time.sleep(0.05)
            except BaseException:
                process.kill()
                process.wait()
                raise
        result = output_path.read_bytes()[:2_000_000].decode("utf-8", errors="replace")
        if process.returncode:
            raise RuntimeError(f"受控命令失败：{result[-1200:]}")
        return result

    def prepare(self) -> Path:
        config = self.db.config()
        if self.project["source_type"] == "inline":
            submissions = self.db.all("SELECT * FROM code_submissions WHERE project_id=? ORDER BY id", (self.project["id"],))
            if not submissions:
                raise ValueError("请先在提交代码页面保存 Python 源码，再启动评估")
            source = self.work / "submitted"
            source.mkdir(parents=True, exist_ok=True)
            for submission in submissions:
                filename = source_filename(submission["filename"])
                target = source / filename
                if not target.resolve().is_relative_to(source.resolve()):
                    raise ValueError("数据库中的提交路径无效")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(submission["code_text"], encoding="utf-8")
        elif self.project["source_type"] == "git":
            if not config["allow_git"]:
                raise ValueError("管理员已关闭仓库接入")
            repository = checked_repository(self.project["source_path"])
            source = self.work / "repository"
            if source.exists():
                remove_tree(source, self.db.root / "workspace")
            environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            environment.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
            self.command([
                "git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
                "-c", "http.followRedirects=false", "-c", "http.proxy=", "-c", "core.hooksPath=" + os.devnull,
                "clone", "--depth", "1", "--no-recurse-submodules", "--", repository, str(source),
            ], env=environment, limit=min(config["default_timeout"], 120))
        else:
            source = checked_local_path(self.project["source_path"], self.db.root)
        self.check()
        if self.project["environment_type"] == "docker":
            self.docker_started = True
            self.command([
                "docker", "create", "--name", self.container, "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64",
                "--memory", "256m", "--cpus", "0.5", "--user", "65534:65534",
                "--mount", f"type=bind,source={source},target=/source,readonly",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", config["docker_image"],
                "python", "-I", "-c", "import time; time.sleep(86400)",
            ])
            self.command(["docker", "start", self.container])
            self.command(["docker", "exec", self.container, "python", "-I", "-c", "import os; print('readonly source:', os.path.isdir('/source'))"])
        return source

    def destroy(self):
        if self.docker_started:
            try:
                result = subprocess.run(["docker", "rm", "-f", self.container], capture_output=True, timeout=15, shell=False)
                return result.returncode == 0 or b"No such container" in result.stderr
            except (OSError, subprocess.TimeoutExpired):
                return False
        return True

    def files(self, source: Path):
        config = self.db.config()
        count = 0
        visited = 0
        for directory, directories, filenames in os.walk(source, followlinks=False):
            self.check()
            directories[:] = sorted(name for name in directories if name not in EXCLUDED and not (Path(directory) / name).is_symlink() and not (Path(directory) / name).is_junction() and (Path(directory) / name).resolve().is_relative_to(source) and not (Path(directory) / name).resolve().is_relative_to(self.db.root))
            for filename in sorted(filenames):
                self.check()
                visited += 1
                if visited > config["max_files"] * 10:
                    raise ValueError("目录条目超过遍历上限，请缩小源码范围")
                path = Path(directory) / filename
                if path.suffix != ".py" or path.is_symlink():
                    continue
                if not path.resolve().is_relative_to(source) or path.stat().st_size > config["max_file_bytes"]:
                    continue
                count += 1
                if count > config["max_files"]:
                    raise ValueError("Python 文件数量超过配置上限")
                yield path


def remove_tree(target: Path, allowed_root: Path):
    resolved = target.resolve()
    root = allowed_root.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise ValueError("拒绝删除存储范围之外的目录")
    if target.is_symlink():
        raise ValueError("拒绝删除符号链接目录")
    if target.exists():
        shutil.rmtree(target)
