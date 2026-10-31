"""Known locations of MCP configs and agent skills on this machine."""
import os
from pathlib import Path
from typing import List


def known_locations() -> List[str]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    candidates = [
        # Claude Desktop
        home / "Library/Application Support/Claude/claude_desktop_config.json",
        home / ".config/Claude/claude_desktop_config.json",
        appdata / "Claude/claude_desktop_config.json",
        # Claude Code
        home / ".claude.json",
        home / ".claude/skills",
        home / ".claude/agents",
        # Cursor, Windsurf, VS Code
        home / ".cursor/mcp.json",
        home / ".codeium/windsurf/mcp_config.json",
        home / "Library/Application Support/Code/User/mcp.json",
        home / ".config/Code/User/mcp.json",
        appdata / "Code/User/mcp.json",
        # Current project
        Path(".mcp.json"),
        Path(".cursor/mcp.json"),
        Path(".vscode/mcp.json"),
        Path(".claude/skills"),
        Path(".claude/agents"),
    ]
    return [str(p) for p in candidates if p.exists()]
