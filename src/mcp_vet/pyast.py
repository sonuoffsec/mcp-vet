"""AST-based analysis for Python MCP servers.

Replaces line regexes for MCP001 / MCP005 and adds MCP009. It tracks which
values come from tool arguments (taint) so that constant commands and
sanitized paths are not flagged.
"""
from __future__ import annotations

import ast
import re
from typing import List, Optional, Set

from .models import Finding
from .rules import RULES

GUARD_ATTRS = {"is_relative_to", "commonpath", "relative_to", "realpath"}
URL_GUARDS = {"urlparse", "hostname", "netloc", "ipaddress", "is_private", "is_loopback"}
# A call to a function with one of these names is assumed to validate its input.
SANITIZER = re.compile(r"(valid|sanit|safe|allow|normali[sz]e|secure|check|quote)", re.I)
SUBPROC = {"run", "call", "check_call", "check_output", "Popen"}
SUBPROC_SHELL_ALWAYS = {"getoutput", "getstatusoutput"}
HTTP_FUNCS = {"get", "post", "put", "delete", "patch", "head", "request", "urlopen"}
HTTP_MODULES = {"requests", "httpx", "urllib.request", "aiohttp"}
SKIP_PARAMS = {"self", "cls", "ctx", "context"}


def dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def is_tool_func(fn) -> bool:
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if dotted(target).rsplit(".", 1)[-1] in ("tool", "call_tool"):
            return True
    return False


def is_constant_expr(node: Optional[ast.AST]) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Call):
        fname = dotted(node.func).rsplit(".", 1)[-1]
        return bool(fname and SANITIZER.search(fname))  # sanitized value counts as clean
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return False
    return all(is_constant_expr(c) for c in ast.iter_child_nodes(node))


def expr_tainted(node: ast.AST, tainted: Set[str]) -> bool:
    if isinstance(node, ast.Call):
        fname = dotted(node.func).rsplit(".", 1)[-1]
        if fname and SANITIZER.search(fname):
            return False
    if isinstance(node, ast.Name):
        return node.id in tainted
    return any(expr_tainted(c, tainted) for c in ast.iter_child_nodes(node))


def _targets(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def taint_set(fn) -> Set[str]:
    a = fn.args
    params = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    if a.vararg:
        params.append(a.vararg.arg)
    if a.kwarg:
        params.append(a.kwarg.arg)
    tainted = {p for p in params if p not in SKIP_PARAMS}
    for _ in range(3):  # propagate through assignments
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and expr_tainted(n.value, tainted):
                for t in n.targets:
                    tainted |= _targets(t)
            elif isinstance(n, (ast.AugAssign, ast.AnnAssign)) and n.value is not None \
                    and expr_tainted(n.value, tainted):
                tainted |= _targets(n.target)
            elif isinstance(n, ast.NamedExpr) and expr_tainted(n.value, tainted):
                tainted |= _targets(n.target)
            elif isinstance(n, (ast.For, ast.AsyncFor)) and expr_tainted(n.iter, tainted):
                tainted |= _targets(n.target)
    return tainted


def _has_guard(fn, names: Set[str]) -> bool:
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and n.attr in names:
            return True
        if isinstance(n, ast.Name) and n.id in names:
            return True
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str, lines: List[str]):
        self.rel, self.lines = rel, lines
        self.findings: List[Finding] = []
        self.stack: List[tuple] = []  # (tainted set, in_tool, guard_path, guard_url)

    def _add(self, rule_id: str, node: ast.AST, severity: str, extra: str = ""):
        r = RULES[rule_id]
        line = getattr(node, "lineno", 1)
        snippet = self.lines[line - 1].strip()[:200] if 0 < line <= len(self.lines) else ""
        msg = r.message + (f" {extra}" if extra else "")
        self.findings.append(Finding(r.id, r.title, severity, self.rel, line, snippet,
                                     msg, r.remediation))

    def _visit_func(self, node):
        if is_tool_func(node):
            self.stack.append((taint_set(node), True,
                               _has_guard(node, GUARD_ATTRS), _has_guard(node, URL_GUARDS)))
        elif self.stack:
            self.stack.append(self.stack[-1])  # nested helper inherits the tool's taint
        else:
            self.stack.append((set(), False, False, False))
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_Call(self, node: ast.Call):
        tainted, in_tool, guard_path, guard_url = self.stack[-1] if self.stack else (set(), False, False, False)
        name = dotted(node.func)
        last = name.rsplit(".", 1)[-1]
        first = node.args[0] if node.args else None
        shell_kw = next((k for k in node.keywords if k.arg == "shell"), None)

        # ---- MCP001: shell / dynamic code -------------------------------------------
        shell_call = name in ("os.system", "os.popen") or \
            (name.startswith("subprocess.") and last in SUBPROC_SHELL_ALWAYS) or \
            (name.startswith("subprocess.") and last in SUBPROC and shell_kw is not None
             and not (isinstance(shell_kw.value, ast.Constant) and not shell_kw.value.value))
        dynamic = name in ("eval", "exec")
        if (shell_call or dynamic) and not is_constant_expr(first):
            if expr_tainted(first, tainted):
                self._add("MCP001", node, "HIGH", "A tool argument reaches this call.")
            else:
                self._add("MCP001", node, "MEDIUM", "The argument is not a constant.")
        elif name.startswith("subprocess.") and last in SUBPROC and isinstance(first, (ast.List, ast.Tuple)) \
                and first.elts and expr_tainted(first.elts[0], tainted):
            self._add("MCP001", node, "HIGH", "A tool argument chooses the program to run.")

        # ---- MCP005: file access with tool-controlled path --------------------------
        if in_tool and not guard_path:
            path_expr = None
            if name == "open" and first is not None:
                path_expr = first
            elif last in ("read_text", "read_bytes", "write_text", "write_bytes") \
                    and isinstance(node.func, ast.Attribute):
                path_expr = node.func.value
            elif last == "open" and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Call):
                path_expr = node.func.value
            if path_expr is not None and expr_tainted(path_expr, tainted):
                self._add("MCP005", node, "MEDIUM", "A tool argument controls the path.")

        # ---- MCP009: outbound request with tool-controlled URL ----------------------
        if in_tool and not guard_url and last in HTTP_FUNCS and first is not None:
            mod = name.rsplit(".", 1)[0] if "." in name else ""
            if mod in HTTP_MODULES or mod.endswith(("session", "client")):
                if expr_tainted(first, tainted):
                    self._add("MCP009", node, "MEDIUM", "A tool argument controls the URL.")

        self.generic_visit(node)


def analyze(rel: str, text: str) -> Optional[List[Finding]]:
    """Return findings, or None if the file cannot be parsed."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    v = _Visitor(rel, text.splitlines())
    v.visit(tree)
    return v.findings
