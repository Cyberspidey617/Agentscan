"""Scanner for MCP server configuration files (Claude, Cursor, VS Code, Windsurf...)."""
import json
import re
from typing import Iterator, List, Tuple
from urllib.parse import urlparse

from .models import Finding, Severity
from .rules import SECRET_PATTERNS, mask_secret, scan_text

SECRET_KEY_NAME = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential)")
PLACEHOLDER = re.compile(r"^\s*$|\$\{[^}]+\}|^\$[A-Z_]+$|<[^>]+>|^(your|xxx|changeme|example|placeholder|todo)", re.I)
RUNNERS = {"npx", "bunx", "uvx", "pipx"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
BROAD_PATHS = {"/", "~", "~/", "$HOME", "${HOME}", "C:\\", "C:/", "/home", "/Users", "%USERPROFILE%"}


def _strip_jsonc(text: str) -> str:
    """Remove // full-line comments and trailing commas (VS Code style JSONC)."""
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    return re.sub(r",(\s*[}\]])", r"\1", text)


def load_config(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(_strip_jsonc(text))


def iter_servers(node) -> Iterator[Tuple[str, dict]]:
    """Find every server definition under any 'mcpServers' or 'servers' key, at any depth."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("mcpServers", "servers", "mcp_servers") and isinstance(value, dict):
                for name, cfg in value.items():
                    if isinstance(cfg, dict):
                        yield name, cfg
            else:
                yield from iter_servers(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_servers(item)


def _line_of(text: str, needle: str) -> int:
    idx = text.find(f'"{needle}"')
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0


def _unpinned_package(command: str, args: List[str]) -> str:
    runner = command.rsplit("/", 1)[-1].lower()
    if runner not in RUNNERS:
        return ""
    for arg in args:
        if arg.startswith("-"):
            continue
        pkg = arg
        if runner in ("uvx", "pipx"):
            return "" if re.search(r"(==|@)\d", pkg) else pkg
        body = pkg[1:] if pkg.startswith("@") else pkg  # scoped packages start with @
        if "@" in body:
            version = body.split("@", 1)[1]
            return pkg if version in ("latest", "next", "") else ""
        return pkg
    return ""


def scan_server(name: str, cfg: dict, path: str, line: int) -> List[Finding]:
    f: List[Finding] = []
    label = f"[{name}] "
    command = str(cfg.get("command", ""))
    args = [str(a) for a in cfg.get("args", []) if a is not None]
    cmdline = " ".join([command] + args)

    pkg = _unpinned_package(command, args)
    if pkg:
        f.append(Finding("AS401", "MCP server package is not version-pinned", Severity.MEDIUM, path, line,
                         label + cmdline[:120],
                         f"Pin an exact version (e.g. {pkg}@1.2.3) so a compromised new release can't run automatically."))

    url = str(cfg.get("url") or cfg.get("serverUrl") or "")
    for candidate in [url] + [a for a in args if a.startswith("http")]:
        if not candidate:
            continue
        parsed = urlparse(candidate)
        if parsed.scheme == "http" and parsed.hostname not in LOCAL_HOSTS:
            f.append(Finding("AS402", "Remote MCP server over unencrypted HTTP", Severity.HIGH, path, line,
                             label + candidate, "Use https:// so tool calls and tokens can't be read or modified in transit."))
        if re.search(r"(?i)[?&](token|key|api_key|apikey|secret|auth)=", "?" + (parsed.query or "")):
            f.append(Finding("AS407", "Credential passed in URL query string", Severity.HIGH, path, line,
                             label + mask_secret(re.sub(r"=([^&]{4})[^&]*", r"=\1****", candidate)),
                             "URLs end up in logs and history. Send credentials in a header from an env variable."))

    for section in ("env", "headers"):
        values = cfg.get(section) or {}
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            value = str(value)
            looks_secret = any(p.search(value) for p in SECRET_PATTERNS)
            named_secret = SECRET_KEY_NAME.search(key) and not PLACEHOLDER.search(value) and len(value) >= 8
            if looks_secret or named_secret:
                f.append(Finding("AS403", f"Hardcoded secret in MCP {section}", Severity.HIGH, path, line,
                                 f"{label}{key}={value[:4]}****",
                                 "Reference an environment variable or input prompt (e.g. ${input:token}) instead of a literal, and rotate this secret."))

    if command.rsplit("/", 1)[-1] in ("docker", "podman"):
        if "--privileged" in args:
            f.append(Finding("AS404", "Container runs with --privileged", Severity.CRITICAL, path, line,
                             label + cmdline[:120], "Drop --privileged; grant only the specific capabilities needed."))
        for a in args:
            if "docker.sock" in a:
                f.append(Finding("AS405", "Docker socket mounted into MCP container", Severity.CRITICAL, path, line,
                                 label + a, "Mounting docker.sock gives the container root on the host. Remove it."))
            m = re.match(r"^(?:-v|--volume=?)?\s*([^:]+):", a)
            if m and m.group(1).rstrip("/") in ("", "~", "$HOME", "/home", "/Users", "/etc", "/root"):
                f.append(Finding("AS406", "Sensitive host path mounted into container", Severity.HIGH, path, line,
                                 label + a, "Mount only the specific project directory the server needs, read-only if possible."))

    for a in args:
        if a.strip() in BROAD_PATHS:
            f.append(Finding("AS408", "Server granted access to an entire disk or home directory", Severity.MEDIUM, path, line,
                             label + cmdline[:120], "Limit filesystem access to the specific project folders the agent needs."))
            break

    if command.rsplit("/", 1)[-1] in ("bash", "sh", "zsh", "cmd", "powershell", "pwsh") or "-c" in args:
        for finding in scan_text(cmdline, path):
            finding.line = line
            finding.evidence = label + finding.evidence
            f.append(finding)

    for key in ("description", "instructions"):
        if isinstance(cfg.get(key), str):
            for finding in scan_text(cfg[key], path):
                finding.line = line
                f.append(finding)
    return f


def scan_mcp_config(text: str, path: str) -> Tuple[List[Finding], int]:
    """Returns (findings, number_of_servers). Raises ValueError if not valid JSON."""
    try:
        data = load_config(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from None
    findings: List[Finding] = []
    count = 0
    for name, cfg in iter_servers(data):
        count += 1
        findings.extend(scan_server(name, cfg, path, _line_of(text, name)))
    return findings, count
