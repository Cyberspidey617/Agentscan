"""Walks files and directories and dispatches to the right scanner."""
import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .mcp import scan_mcp_config
from .models import Finding
from .rules import scan_text

TEXT_EXTENSIONS = {".md", ".markdown", ".txt", ".py", ".sh", ".bash", ".zsh", ".ps1", ".js", ".mjs", ".cjs",
                   ".ts", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".rb", ".go", ".rs", ".html", ""}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox", ".mypy_cache"}
MAX_BYTES = 2_000_000


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    servers_scanned: int = 0
    errors: List[str] = field(default_factory=list)


def _is_mcp_config(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix in (".json", ".jsonc") and (
        "mcp" in name or name in ("claude_desktop_config.json", ".claude.json", "settings.json"))


def scan_file(path: Path, result: ScanResult) -> None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return
    result.files_scanned += 1
    display = str(path)
    if _is_mcp_config(path):
        try:
            findings, count = scan_mcp_config(text, display)
            result.servers_scanned += count
            result.findings.extend(findings)
            if count or path.name != "settings.json":
                return
        except ValueError as exc:
            result.errors.append(f"{display}: {exc}")
    result.findings.extend(scan_text(text, display))


def _excluded(path: Path, excludes: List[str]) -> bool:
    posix = path.as_posix().lstrip("./")
    return any(fnmatch.fnmatch(posix, g) or fnmatch.fnmatch(path.name, g) for g in excludes)


def scan_path(target: str, result: ScanResult, excludes: Optional[List[str]] = None) -> None:
    excludes = excludes or []
    path = Path(os.path.expanduser(target))
    if not path.exists():
        result.errors.append(f"{target}: not found")
        return
    if path.is_file():
        scan_file(path, result)
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            p = Path(root) / name
            if p.suffix.lower() in TEXT_EXTENSIONS and not _excluded(p, excludes):
                scan_file(p, result)


def dedupe(findings: List[Finding]) -> List[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.rule_id, f.file, f.line, f.evidence)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
