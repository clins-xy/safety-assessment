import ast
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePosixPath
import stat
from zipfile import BadZipFile, ZipFile


MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_SOURCE_FILES = 200
MAX_ARCHIVE_ENTRIES = 10000
IGNORED_DIRECTORIES = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".idea",
    ".agents", ".codex", ".aws", "data", "__MACOSX", "dist", "build",
}
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}


def source_filename(value: str) -> str:
    value = value.replace("\\", "/")
    parts = value.split("/")
    if not value or len(value) > 180 or value.startswith("/") or any(
        part in ("", ".", "..") or part.endswith((".", " "))
        or part.split(".", 1)[0].upper() in WINDOWS_RESERVED
        or any(ord(c) < 32 or c in '<>:"|?*' for c in part)
        for part in parts
    ):
        raise ValueError("源码路径无效或过长，不能包含绝对路径、上级目录或系统保留名称")
    if not value.lower().endswith(".py") or PurePosixPath(value).name.lower() == ".py":
        raise ValueError("请上传 .py 文件或包含 Python 源码的 ZIP")
    return value


@dataclass
class ImportedSource:
    filename: str
    code: str
    size: int


@dataclass
class ImportResult:
    sources: list[ImportedSource]
    skipped: int


def collect_sources(uploads: list[tuple[str, bytes]], code: str = "", filename: str = "submitted.py", max_files=MAX_SOURCE_FILES) -> ImportResult:
    sources: list[ImportedSource] = []
    seen: set[str] = set()
    total_bytes = 0
    skipped = 0
    visited = 0

    def add(name: str, data: bytes):
        nonlocal total_bytes, skipped
        normalized = name.replace("\\", "/")
        if any(part in IGNORED_DIRECTORIES or part.startswith(".") for part in normalized.split("/")[:-1]) or not normalized.lower().endswith(".py"):
            skipped += 1
            return
        name = source_filename(normalized)
        key = name.casefold()
        if key in seen:
            raise ValueError(f"存在重复的源码路径：{name}")
        if any(key.startswith(previous + "/") or previous.startswith(key + "/") for previous in seen):
            raise ValueError(f"源码文件与目录名称冲突：{name}")
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError(f"{name} 超过单文件 1 MiB 上限")
        total_bytes += len(data)
        if total_bytes > MAX_UPLOAD_BYTES:
            raise ValueError("解压后的 Python 源码合计不能超过 20 MiB")
        if len(sources) >= min(max_files, MAX_SOURCE_FILES):
            raise ValueError(f"一次最多导入 {min(max_files, MAX_SOURCE_FILES)} 个 Python 文件")
        try:
            text = data.decode("utf-8-sig")
            ast.parse(text, filename=name)
        except UnicodeError:
            raise ValueError(f"{name} 不是 UTF-8 编码，请转换后重新上传") from None
        except (SyntaxError, ValueError, RecursionError) as error:
            line = getattr(error, "lineno", None)
            raise ValueError(f"{name}{':' + str(line) if line else ''} 无法解析为 Python 源码，请修正后重试") from None
        sources.append(ImportedSource(name, text, len(data)))
        seen.add(key)

    if code:
        if uploads:
            raise ValueError("请选择上传文件或粘贴代码，不要同时提交")
        add(filename, code.encode("utf-8"))
    for name, data in uploads:
        if not name.lower().endswith(".zip"):
            add(name, data)
            continue
        try:
            with ZipFile(BytesIO(data)) as archive:
                entries = archive.infolist()
                visited += len(entries)
                if visited > MAX_ARCHIVE_ENTRIES:
                    raise ValueError("ZIP 文件条目过多，请移除依赖和构建目录后重试")
                for entry in entries:
                    if entry.is_dir():
                        continue
                    normalized = entry.filename.replace("\\", "/")
                    if normalized.startswith("/") or ".." in normalized.split("/") or ":" in normalized:
                        raise ValueError("ZIP 包含不安全的文件路径")
                    if stat.S_ISLNK(entry.external_attr >> 16):
                        raise ValueError("ZIP 不能包含符号链接")
                    if not normalized.lower().endswith(".py") or any(part in IGNORED_DIRECTORIES or part.startswith(".") for part in normalized.split("/")[:-1]):
                        skipped += 1
                        continue
                    if entry.flag_bits & 1:
                        raise ValueError("不能导入加密的源码 ZIP")
                    if entry.file_size > MAX_SOURCE_BYTES:
                        raise ValueError(f"{normalized} 超过单文件 1 MiB 上限")
                    with archive.open(entry) as stream:
                        add(normalized, stream.read(MAX_SOURCE_BYTES + 1))
        except (BadZipFile, NotImplementedError, RuntimeError, OSError, EOFError):
            raise ValueError("ZIP 已损坏、被加密或压缩格式不受支持") from None
    if not sources:
        raise ValueError("没有找到可评估的 Python 源码，请上传 .py 文件、源码 ZIP 或直接粘贴代码")
    return ImportResult(sources, skipped)
