"""Find the MCP client configuration files on this machine.

mcp-vet only reads these files and prints findings. Nothing is sent anywhere.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Mapping, Optional


def candidate_paths(home: Optional[Path] = None, env: Optional[Mapping[str, str]] = None,
                    cwd: Optional[Path] = None) -> List[Path]:
    """Every place a supported client keeps its MCP servers, whether or not the file exists."""
    home = home or Path.home()
    env = os.environ if env is None else env
    cwd = cwd or Path.cwd()
    appdata = Path(env["APPDATA"]) if env.get("APPDATA") else None
    xdg = Path(env["XDG_CONFIG_HOME"]) if env.get("XDG_CONFIG_HOME") else home / ".config"
    mac = home / "Library" / "Application Support"

    out: List[Path] = []
    for base in filter(None, [appdata, mac, xdg]):
        out.append(base / "Claude" / "claude_desktop_config.json")   # Claude Desktop
        out.append(base / "Code" / "User" / "mcp.json")               # VS Code (user)
    out += [
        home / ".cursor" / "mcp.json",                                # Cursor (user)
        home / ".codeium" / "windsurf" / "mcp_config.json",           # Windsurf
        home / ".claude.json",                                        # Claude Code (user)
        cwd / ".vscode" / "mcp.json",                                 # VS Code (project)
        cwd / ".cursor" / "mcp.json",                                 # Cursor (project)
        cwd / ".mcp.json",                                            # Claude Code (project)
    ]
    return out


def existing_configs(home: Optional[Path] = None, env: Optional[Mapping[str, str]] = None,
                     cwd: Optional[Path] = None) -> List[Path]:
    seen, found = set(), []
    for p in candidate_paths(home, env, cwd):
        try:
            key = p.resolve()
        except OSError:
            continue
        if p.is_file() and key not in seen:
            seen.add(key)
            found.append(p)
    return found


def display(path: Path, home: Optional[Path] = None) -> str:
    """The path with the home folder shown as ~, so pasted output does not reveal the user name."""
    home = home or Path.home()
    try:
        return "~/" + path.resolve().relative_to(home.resolve()).as_posix()
    except ValueError:
        return path.as_posix()
