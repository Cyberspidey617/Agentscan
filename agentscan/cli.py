import argparse
import sys

from . import __version__
from .discover import known_locations
from .models import Severity
from .report import list_rules, render_json, render_sarif, render_text
from .scanner import ScanResult, dedupe, scan_path

EPILOG = """examples:
  agentscan --auto                       scan MCP configs & skills found on this machine
  agentscan ~/.claude/skills             scan a folder of agent skills
  agentscan .cursor/mcp.json             scan one MCP config
  agentscan . --format sarif -o out.sarif   report for GitHub code scanning
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentscan", epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
                                description="Scan MCP servers and AI agent skills for prompt injection, "
                                            "tool poisoning, secrets and risky commands.")
    p.add_argument("paths", nargs="*", help="files or directories to scan")
    p.add_argument("--auto", action="store_true", help="auto-discover Claude, Cursor, VS Code and Windsurf configs")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", help="write report to a file instead of stdout")
    p.add_argument("--min-severity", default="low", help="hide findings below this level (default: low)")
    p.add_argument("--fail-on", default="high",
                   help="exit with code 1 if any finding is at or above this level (default: high; 'none' to disable)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching this glob, e.g. --exclude 'tests/*' (repeatable)")
    p.add_argument("--list-rules", action="store_true", help="show all detection rules and exit")
    p.add_argument("--version", action="version", version=f"agentscan {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        sys.stdout.write(list_rules())
        return 0
    try:
        min_sev = Severity.parse(args.min_severity)
        fail_on = None if args.fail_on.lower() == "none" else Severity.parse(args.fail_on)
    except ValueError as exc:
        print(f"agentscan: {exc}", file=sys.stderr)
        return 2

    targets = list(args.paths)
    if args.auto:
        found = known_locations()
        if not found:
            print("agentscan: no known MCP configs or skill folders found on this machine", file=sys.stderr)
        targets.extend(found)
        if not targets:
            return 0
    if not targets:
        targets = ["."]

    result = ScanResult()
    for target in targets:
        scan_path(target, result, args.exclude)
    findings = [f for f in dedupe(result.findings) if f.severity >= min_sev]

    out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        if args.format == "json":
            out.write(render_json(result, findings))
        elif args.format == "sarif":
            out.write(render_sarif(result, findings))
        else:
            out.write(render_text(result, findings, out))
    finally:
        if args.output:
            out.close()

    if fail_on is not None and any(f.severity >= fail_on for f in findings):
        return 1
    return 0
