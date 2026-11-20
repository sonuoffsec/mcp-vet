"""File-level checks that need more than a single-line regex."""
from __future__ import annotations

import json
import re
from typing import List, Optional

from .models import Finding
from .rules import RULES, CODE_EXTS

TOOL_MARKERS = re.compile(
    r"(@\w+\.tool\b|\bserver\.tool\(|registerTool|@tool\b|setRequestHandler|CallToolRequestSchema|FastMCP)"
)
NET_TRANSPORT = re.compile(
    r"(transport\s*=\s*['\"](sse|streamable-http|http)['\"]"
    r"|SSEServerTransport|StreamableHTTPServerTransport|SseServerTransport"
    r"|sse_app\(|streamable_http_app\(|\bapp\.listen\()"
)
AUTH_HINT = re.compile(
    r"(authorization|bearer|api[_-]?key|oauth|auth_?middleware|verify_?token|jwt|x-api-key)",
    re.IGNORECASE,
)
OPEN_BIND = re.compile(r"0\.0\.0\.0|host\s*=\s*['\"]::['\"]")
FILE_READ = re.compile(
    r"(\bopen\s*\(|\.read_text\s*\(|\.read_bytes\s*\(|\breadFile(Sync)?\s*\(|createReadStream\s*\()"
)
PATH_GUARD = re.compile(
    r"(is_relative_to|commonpath|\.relative_to\(|realpath|path\.relative\(|startsWith\(\s*(root|base|allowed|safe))",
    re.IGNORECASE,
)
BROAD_SCOPES = {"/", "~", "~/", "c:\\", "c:/", "c:\\\\", "/home", "/users", "/root"}


def _finding(rule_id: str, file: str, line: int, snippet: str, extra: str = "") -> Finding:
    r = RULES[rule_id]
    msg = r.message + (f" {extra}" if extra else "")
    return Finding(r.id, r.title, r.severity, file, line, snippet.strip()[:200], msg, r.remediation)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def check_network_auth(file: str, text: str, ext: str,
                       project_has_auth: Optional[bool] = None) -> List[Finding]:
    """project_has_auth: True if ANY code file in the project shows auth handling."""
    if ext not in CODE_EXTS or not TOOL_MARKERS.search(text):
        return []
    has_auth = AUTH_HINT.search(text) is not None if project_has_auth is None else project_has_auth
    net = NET_TRANSPORT.search(text)
    if not net or has_auth:
        return []
    bind = OPEN_BIND.search(text)
    anchor = bind or net
    line = _line_of(text, anchor.start())
    snippet = text.splitlines()[line - 1]
    f = _finding("MCP004", file, line, snippet,
                 "It also binds to all interfaces." if bind else "")
    return [f]


def check_file_read(file: str, text: str, ext: str,
                    project_has_guard: Optional[bool] = None) -> List[Finding]:
    """Regex fallback for JS/TS (Python uses pyast). project_has_guard looks across files."""
    if ext not in CODE_EXTS or not TOOL_MARKERS.search(text):
        return []
    has_guard = PATH_GUARD.search(text) is not None if project_has_guard is None else project_has_guard
    read = FILE_READ.search(text)
    if not read or has_guard:
        return []
    line = _line_of(text, read.start())
    return [_finding("MCP005", file, line, text.splitlines()[line - 1])]


def check_dependencies(file: str, text: str, name: str) -> List[Finding]:
    out: List[Finding] = []
    lname = name.lower()
    if lname.startswith("requirements") and lname.endswith(".txt"):
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            if "==" in line or " @ " in line or line.startswith(("git+", "http")):
                continue
            out.append(_finding("MCP006", file, i, raw))
    elif lname == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return out
        for section in ("dependencies", "devDependencies"):
            for pkg, ver in (data.get(section) or {}).items():
                if str(ver).strip() in ("*", "latest", "", "x"):
                    needle = f'"{pkg}"'
                    idx = text.find(needle)
                    line = _line_of(text, idx) if idx >= 0 else 1
                    out.append(_finding("MCP006", file, line, f'{pkg}: "{ver}"'))
    return out


def check_broad_scope(file: str, text: str, ext: str) -> List[Finding]:
    if ext != ".json":
        return []
    out: List[Finding] = []
    for m in re.finditer(r'"args"\s*:\s*\[(.*?)\]', text, re.S):
        for item in re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1)):
            if item.strip().lower() in BROAD_SCOPES:
                line = _line_of(text, m.start(1) + m.group(1).find(f'"{item}"'))
                out.append(_finding("MCP007", file, line, f'"args": [... "{item}" ...]'))
    return out
