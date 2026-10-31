"""Output formats: colored terminal text, JSON and SARIF (GitHub code scanning)."""
import json
import os
import sys
from collections import Counter
from typing import List

from . import __version__
from .models import Finding, Severity
from .rules import TEXT_RULES

WEIGHTS = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 8, Severity.LOW: 3, Severity.INFO: 0}
COLORS = {Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;91m", Severity.MEDIUM: "\033[1;93m",
          Severity.LOW: "\033[1;94m", Severity.INFO: "\033[2m"}
RESET, BOLD, DIM, GREEN = "\033[0m", "\033[1m", "\033[2m", "\033[1;92m"


def score(findings: List[Finding]) -> int:
    return max(0, 100 - sum(WEIGHTS[f.severity] for f in findings))


def grade(value: int) -> str:
    for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if value >= threshold:
            return letter
    return "F"


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def render_text(result, findings: List[Finding], stream=sys.stdout) -> str:
    color = _use_color(stream)
    c = (lambda code, s: f"{code}{s}{RESET}") if color else (lambda code, s: s)
    out = [c(BOLD, f"agentscan v{__version__}") + c(DIM, f"  ·  {result.files_scanned} files, "
                                                       f"{result.servers_scanned} MCP servers scanned"), ""]
    for f in sorted(findings, key=lambda x: (-x.severity, x.file, x.line)):
        loc = f"{f.file}:{f.line}" if f.line else f.file
        out.append(f"{c(COLORS[f.severity], f' {f.severity.name:<8} ')} {c(BOLD, f.rule_id)}  {f.title}")
        out.append(f"           {c(DIM, loc)}")
        if f.evidence:
            out.append(f"           > {f.evidence}")
        if f.fix:
            out.append(f"           {c(GREEN, 'fix:')} {f.fix}")
        out.append("")
    for err in result.errors:
        out.append(c(DIM, f"warning: {err}"))
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s.name.lower()}" for s in sorted(counts, reverse=True)) or "no issues found"
    s = score(findings)
    s_color = GREEN if s >= 75 else COLORS[Severity.MEDIUM] if s >= 40 else COLORS[Severity.HIGH]
    out.append(f"{c(BOLD, 'Result:')} {summary}")
    out.append(f"{c(BOLD, 'Security score:')} {c(s_color, f'{s}/100 (grade {grade(s)})')}")
    return "\n".join(out) + "\n"


def render_json(result, findings: List[Finding]) -> str:
    s = score(findings)
    return json.dumps({
        "tool": "agentscan", "version": __version__,
        "files_scanned": result.files_scanned, "servers_scanned": result.servers_scanned,
        "score": s, "grade": grade(s),
        "findings": [f.to_dict() for f in findings], "errors": result.errors,
    }, indent=2, ensure_ascii=False) + "\n"


SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note"}


def render_sarif(result, findings: List[Finding]) -> str:
    rules = {}
    for f in findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id, "name": f.rule_id, "shortDescription": {"text": f.title},
            "help": {"text": f.fix or f.title},
            "properties": {"security-severity": {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0",
                                                 Severity.MEDIUM: "5.5", Severity.LOW: "3.0",
                                                 Severity.INFO: "0.0"}[f.severity]},
        })
    results = []
    for f in findings:
        uri = os.path.relpath(f.file) if not f.file.startswith("~") else f.file
        results.append({
            "ruleId": f.rule_id, "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}. {f.evidence}".strip()},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri.replace(os.sep, "/")},
                "region": {"startLine": max(f.line, 1)}}}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "agentscan", "version": __version__,
                                      "informationUri": "https://github.com/YOUR_USERNAME/agentscan",
                                      "rules": list(rules.values())}},
                  "results": results}],
    }, indent=2) + "\n"


def list_rules() -> str:
    extra = [
        ("AS110", "CRITICAL", "Hidden Unicode tag characters (ASCII smuggling)"),
        ("AS111", "HIGH", "Bidirectional override characters (Trojan Source)"),
        ("AS112", "MEDIUM", "Zero-width characters hidden in text"),
        ("AS301", "HIGH", "Hardcoded secret or private key"),
        ("AS401", "MEDIUM", "MCP server package is not version-pinned"),
        ("AS402", "HIGH", "Remote MCP server over unencrypted HTTP"),
        ("AS403", "HIGH", "Hardcoded secret in MCP env/headers"),
        ("AS404", "CRITICAL", "Container runs with --privileged"),
        ("AS405", "CRITICAL", "Docker socket mounted into MCP container"),
        ("AS406", "HIGH", "Sensitive host path mounted into container"),
        ("AS407", "HIGH", "Credential passed in URL query string"),
        ("AS408", "MEDIUM", "Server granted access to an entire disk or home directory"),
    ]
    rows = [(r.rule_id, r.severity.name, r.title) for r in TEXT_RULES] + extra
    return "\n".join(f"{rid}  {sev:<8}  {title}" for rid, sev, title in sorted(rows)) + "\n"
