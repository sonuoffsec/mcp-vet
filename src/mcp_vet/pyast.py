"""AST-based analysis for Python MCP servers.

Replaces line regexes for MCP001 / MCP005 and adds MCP009 / MCP010 / MCP011. It tracks which
values come from tool arguments (taint) so that constant commands and sanitized paths are
not flagged. Taint follows assignments inside a function, and one hop into helper functions
defined in the same file.
"""
from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Set, Tuple

from .models import Finding
from .rules import RULES

GUARD_ATTRS = {"is_relative_to", "commonpath", "relative_to", "realpath"}
URL_GUARDS = {"urlparse", "hostname", "netloc", "ipaddress", "is_private", "is_loopback"}
# A call to a function with one of these names is assumed to validate its input.
SANITIZER = re.compile(r"(valid|sanit|safe|allow|normali[sz]e|secure|check|quote|resolve_|confine|within|inside|contain|jail|sandbox)", re.I)
SUBPROC = {"run", "call", "check_call", "check_output", "Popen"}
SUBPROC_SHELL_ALWAYS = {"getoutput", "getstatusoutput"}
SHELL_PROGRAMS = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "powershell", "pwsh"}
# A fixed interpreter still runs whatever code or script it is handed: ["python", "-c", user_code].
INTERPRETERS = SHELL_PROGRAMS | {"python", "python2", "python3", "node", "nodejs", "deno", "bun",
                                 "ruby", "perl", "php"}
EXEC_FUNCS = {"os.execv", "os.execve", "os.execvp", "os.execvpe", "os.execl", "os.execle",
              "os.execlp", "os.execlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
              "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe", "os.startfile"}
HTTP_FUNCS = {"get", "post", "put", "delete", "patch", "head", "request", "urlopen"}
HTTP_MODULES = {"requests", "httpx", "urllib.request", "aiohttp"}
HTTP_CLIENT_FACTORIES = {"httpx.Client", "httpx.AsyncClient", "requests.Session",
                         "aiohttp.ClientSession", "urllib3.PoolManager"}
PATH_FUNCS = {"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.listdir", "os.scandir",
              "os.rename", "os.replace", "os.makedirs", "os.mkdir", "os.walk", "os.chmod",
              "os.symlink", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree",
              "shutil.move", "shutil.rmtree"}
PATH_FUNC_NAMES = {"send_file", "FileResponse"}  # send_from_directory is the safe API
# Unambiguous Path methods, flagged on any tainted receiver.
PATH_READ_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes"}
# Ambiguous names (str.replace!) are only flagged when the receiver is clearly a Path.
PATH_OTHER_METHODS = {"unlink", "rmdir", "iterdir", "mkdir", "rename", "replace", "glob", "rglob",
                      "touch", "chmod", "symlink_to", "hardlink_to"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "exec_driver_sql",
               "read_sql", "read_sql_query"}
DESERIALIZERS = {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load", "dill.loads",
                 "dill.load", "cloudpickle.loads", "jsonpickle.decode", "yaml.unsafe_load"}
SAFE_YAML_LOADERS = ("SafeLoader", "CSafeLoader", "BaseLoader")
ROUTE_VERBS = {"get", "post", "put", "delete", "patch", "route", "api_route", "websocket"}
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
    """A tool handler, or an HTTP route handler (FastAPI/Flask): both receive attacker input."""
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        last = dotted(target).rsplit(".", 1)[-1]
        if last in ("tool", "call_tool"):
            return True
        if isinstance(d, ast.Call) and last in ROUTE_VERBS and d.args \
                and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str) \
                and d.args[0].value.startswith("/"):
            return True
    # Servers that dispatch by name (`if tool_name == "execute_code": self.execute_code(...)`)
    # register their tools in a schema; a function named after a registered tool handles it.
    name = fn.name
    base = name[1:] if name.startswith("_") else name
    base = base[len("handle_"):] if base.startswith("handle_") else base
    return name in _TOOL_NAMES or base in _TOOL_NAMES


def _schema_tool_names(tree: ast.AST) -> Set[str]:
    """Names from tool-schema dicts such as {"name": "read_file", "description": ..., "inputSchema": ...}."""
    out: Set[str] = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Dict):
            continue
        keys = {k.value: v for k, v in zip(n.keys, n.values)
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        label = keys.get("name")
        if isinstance(label, ast.Constant) and isinstance(label.value, str) \
                and keys.keys() & {"description", "inputSchema", "input_schema", "parameters", "schema"}:
            out.add(label.value)
    return out


def is_constant_expr(node: Optional[ast.AST]) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Call):
        fname = dotted(node.func).rsplit(".", 1)[-1]
        return bool(fname and SANITIZER.search(fname))  # sanitized value counts as clean
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return False
    return all(is_constant_expr(c) for c in ast.iter_child_nodes(node))


# Module-level helpers whose return value does not carry their inputs (set per file by analyze()).
_CLEAN_FUNCS: Set[str] = set()
# Tool names found in schema dicts, so name-dispatched handlers are recognised (set per file).
_TOOL_NAMES: Set[str] = set()


def expr_tainted(node: ast.AST, tainted: Set[str]) -> bool:
    if isinstance(node, ast.Call):
        fname = dotted(node.func).rsplit(".", 1)[-1]
        if fname and SANITIZER.search(fname):
            return False
        if isinstance(node.func, ast.Name) and node.func.id in _CLEAN_FUNCS:
            return False  # e.g. a query builder that returns "WHERE a = ?" and a separate params list
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        # The result is built from the element expression. Iterating tainted data does not
        # taint it unless the element expression uses the loop variable without sanitizing it.
        local = set(tainted)
        for g in node.generators:
            if expr_tainted(g.iter, tainted):
                local |= _targets(g.target)
        parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
        return any(expr_tainted(p, local) for p in parts)
    if isinstance(node, ast.Name):
        return node.id in tainted
    return any(expr_tainted(c, tainted) for c in ast.iter_child_nodes(node))


def is_interpolated(node: ast.AST) -> bool:
    """True if the expression builds a string from pieces (f-string, +, %, .format)."""
    for n in ast.walk(node):
        if isinstance(n, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in n.values):
            return True
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
            return True
    return False


SQL_WORDS = re.compile(r"\b(select|insert|update|delete|create|drop|alter|truncate|union|where|from|into|values)\b", re.I)


def _sql_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and bool(SQL_WORDS.search(node.value))


def is_sql_interpolation(node: ast.AST) -> bool:
    """f-string, +, % or .format whose literal parts look like SQL. ORM expressions that merely
    contain an f-string value do not count."""
    for n in ast.walk(node):
        if isinstance(n, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in n.values) \
                and any(_sql_literal(v) for v in n.values):
            return True
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)) \
                and (_sql_literal(n.left) or _sql_literal(n.right)):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format" \
                and _sql_literal(n.func.value):
            return True
    return False


def raw_params(fn) -> Set[str]:
    a = fn.args
    names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return {n for n in names if n not in SKIP_PARAMS}


def sql_built_names(fn, tainted: Set[str]) -> Set[str]:
    """Variables holding a SQL string that was built from tainted pieces."""
    out: Set[str] = set()
    for n in ast.walk(fn):
        value, targets = None, []
        if isinstance(n, ast.Assign):
            value, targets = n.value, n.targets
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)) and n.value is not None:
            value, targets = n.value, [n.target]
        if value is not None and is_sql_interpolation(value) and expr_tainted(value, tainted):
            for t in targets:
                out |= _targets(t)
    return out


def _url_host_is_fixed(node: ast.AST) -> bool:
    """f"https://api.example.org/v1/{x}" or "https://api.example.org/" + x: scheme and host are constant."""
    head = None
    if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
        head = node.values[0].value
    else:
        while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            node = node.left
        if isinstance(node, ast.Constant):
            head = node.value
    return isinstance(head, str) and re.match(r"^https?://[^/?#]+[/?#]", head) is not None


def is_path_like(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        return dotted(node.func).rsplit(".", 1)[-1] in ("Path", "PurePath", "PosixPath", "WindowsPath")
    return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)


def _targets(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def validated_names(fn) -> Set[str]:
    """Names checked with `in` / `not in` against a collection in an if that returns or raises."""
    out: Set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.If) and any(isinstance(b, (ast.Return, ast.Raise)) for b in n.body + n.orelse):
            for c in ast.walk(n.test):
                if isinstance(c, ast.Compare) and isinstance(c.left, ast.Name) \
                        and any(isinstance(o, (ast.In, ast.NotIn)) for o in c.ops) \
                        and not any(isinstance(x, ast.Constant) and isinstance(x.value, str)
                                    for x in c.comparators):
                    out.add(c.left.id)
    out |= _validated_by_lookup(fn)
    return out


EXISTENCE_CHECKS = {"exists", "isfile", "isdir", "is_file", "is_dir", "lexists", "access", "islink"}


def _validated_by_lookup(fn) -> Set[str]:
    """`if registry.get(x) is None: raise` validates x. An existence check on the filesystem does not."""
    out: Set[str] = set()

    def lookup_call(node):
        call = node.operand if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) else node
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Is, ast.IsNot))                 and isinstance(node.comparators[0], ast.Constant) and node.comparators[0].value is None:
            call = node.left
        if not isinstance(call, ast.Call):
            return None
        name = dotted(call.func)
        if name.split(".")[0] in ("os", "shutil", "pathlib") or name.rsplit(".", 1)[-1] in EXISTENCE_CHECKS:
            return None
        return call

    for n in ast.walk(fn):
        if isinstance(n, ast.If) and any(isinstance(b, (ast.Return, ast.Raise)) for b in n.body + n.orelse):
            for t in ast.walk(n.test):
                call = lookup_call(t)
                if call is not None:
                    for a in call.args:
                        if isinstance(a, ast.Name):
                            out.add(a.id)
    return out


def taint_set(fn, include_request: bool = True, only: Optional[Set[str]] = None) -> Set[str]:
    a = fn.args
    params = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    if a.vararg:
        params.append(a.vararg.arg)
    if a.kwarg:
        params.append(a.kwarg.arg)
    if only is not None:  # helper summaries: make just this parameter hostile
        params = [p for p in params if p in only]
    # Flask and Quart expose the incoming request as a module-level global, not a parameter.
    val = validated_names(fn)  # checked against an allowlist: never tainted, even when derived
    tainted = ({p for p in params if p not in SKIP_PARAMS} | ({"request"} if include_request else set())) - val
    for _ in range(3):  # propagate through assignments
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and expr_tainted(n.value, tainted):
                for t in n.targets:
                    tainted |= _targets(t) - val
            elif isinstance(n, (ast.AugAssign, ast.AnnAssign)) and n.value is not None \
                    and expr_tainted(n.value, tainted):
                tainted |= _targets(n.target) - val
            elif isinstance(n, ast.NamedExpr) and expr_tainted(n.value, tainted):
                tainted |= _targets(n.target) - val
            elif isinstance(n, (ast.For, ast.AsyncFor)) and expr_tainted(n.iter, tainted):
                tainted |= _targets(n.target) - val
    return tainted


def _has_guard(fn, names: Set[str]) -> bool:
    for n in ast.walk(fn):
        if isinstance(n, ast.Attribute) and n.attr in names:
            return True
        if isinstance(n, ast.Name) and n.id in names:
            return True
    return False


def _http_clients(tree: ast.AST) -> Set[str]:
    """Names bound to an HTTP client object, e.g. `async with httpx.AsyncClient() as c`."""
    out: Set[str] = set()

    def is_factory(expr) -> bool:
        return isinstance(expr, ast.Call) and dotted(expr.func) in HTTP_CLIENT_FACTORIES

    for n in ast.walk(tree):
        if isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if is_factory(item.context_expr) and item.optional_vars is not None:
                    out.add(dotted(item.optional_vars))
        elif isinstance(n, ast.Assign) and is_factory(n.value):
            for t in n.targets:
                out.add(dotted(t))
        elif isinstance(n, ast.AnnAssign) and n.value is not None and is_factory(n.value):
            out.add(dotted(n.target))
    out.discard("")
    return out


# helper name -> (positional parameter names, {parameter name -> findings if it is hostile})
Summaries = Dict[str, Tuple[List[str], Dict[str, List[Tuple[str, str]]]]]


class _Visitor(ast.NodeVisitor):
    def __init__(self, rel: str, lines: List[str], http_clients: Set[str],
                 summaries: Optional[Summaries] = None):
        self.rel, self.lines, self.http_clients = rel, lines, http_clients
        self.summaries: Summaries = summaries or {}
        self.findings: List[Finding] = []
        self.stack: List[tuple] = []  # (tainted, in_tool, guard_path, guard_url, raw params, sql built)

    def _add(self, rule_id: str, node: ast.AST, severity: str, extra: str = ""):
        r = RULES[rule_id]
        line = getattr(node, "lineno", 1)
        snippet = self.lines[line - 1].strip()[:200] if 0 < line <= len(self.lines) else ""
        msg = r.message + (f" {extra}" if extra else "")
        self.findings.append(Finding(r.id, r.title, severity, self.rel, line, snippet,
                                     msg, r.remediation))

    def _visit_func(self, node):
        if is_tool_func(node):
            t = taint_set(node)
            self.stack.append((t, True, _has_guard(node, GUARD_ATTRS), _has_guard(node, URL_GUARDS),
                               raw_params(node), sql_built_names(node, t)))
        elif self.stack:
            self.stack.append(self.stack[-1])  # nested helper inherits the tool's taint
        else:
            self.stack.append((set(), False, False, False, set(), set()))
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_Call(self, node: ast.Call):
        tainted, in_tool, guard_path, guard_url, params, sql_built = \
            self.stack[-1] if self.stack else (set(), False, False, False, set(), set())
        name = dotted(node.func)
        last = node.func.attr if isinstance(node.func, ast.Attribute) else name
        first = node.args[0] if node.args else None
        shell_kw = next((k for k in node.keywords if k.arg == "shell"), None)
        any_arg_tainted = any(expr_tainted(a, tainted) and not is_constant_expr(a) for a in node.args)

        # ---- MCP001: shell / dynamic code / program chosen by the caller ------------
        obfuscated = isinstance(node.func, ast.Attribute) and last in ("system", "popen") \
            and isinstance(node.func.value, ast.Call) and dotted(node.func.value.func) == "__import__"
        shell_call = obfuscated or name in ("os.system", "os.popen") or last == "create_subprocess_shell" or \
            (name.startswith("subprocess.") and last in SUBPROC_SHELL_ALWAYS) or \
            (name.startswith("subprocess.") and last in SUBPROC and shell_kw is not None
             and not (isinstance(shell_kw.value, ast.Constant) and not shell_kw.value.value))
        dynamic = name in ("eval", "exec")
        if (shell_call or dynamic) and not is_constant_expr(first):
            if expr_tainted(first, tainted):
                self._add("MCP001", node, "HIGH", "A tool argument reaches this call.")
            elif not (in_tool and any(isinstance(n, ast.Name) and n.id in params and n.id not in tainted
                                      for n in ast.walk(first))):
                # (skipped when the only inputs used were validated against an allowlist)
                self._add("MCP001", node, "MEDIUM", "The argument is not a constant.")
        elif name.startswith("subprocess.") and last in SUBPROC and first is not None and \
                self._program_from_input(first, tainted):
            self._add("MCP001", node, "HIGH", "A tool argument chooses the program to run.")
        elif last == "create_subprocess_exec" and node.args and \
                self._program_from_input(ast.List(elts=list(node.args), ctx=ast.Load()), tainted):
            self._add("MCP001", node, "HIGH", "A tool argument is run as code or chooses the program.")
        elif name in EXEC_FUNCS and any_arg_tainted:
            self._add("MCP001", node, "HIGH", "A tool argument chooses the program to run.")

        # ---- MCP005: file access with a caller-controlled path ----------------------
        if in_tool and not guard_path:
            path_exprs: List[ast.AST] = []
            if name == "open" and first is not None:
                path_exprs.append(first)
            elif last in PATH_READ_METHODS and isinstance(node.func, ast.Attribute):
                path_exprs.append(node.func.value)
            elif last == "open" and isinstance(node.func, ast.Attribute) \
                    and isinstance(node.func.value, ast.Call):
                path_exprs.append(node.func.value)
            elif last in PATH_OTHER_METHODS and isinstance(node.func, ast.Attribute) \
                    and is_path_like(node.func.value):
                path_exprs.append(node.func.value)
            elif name in PATH_FUNCS or last in PATH_FUNC_NAMES or name in PATH_FUNC_NAMES:
                path_exprs.extend(node.args)
            if any(expr_tainted(p, tainted) and not is_constant_expr(p) for p in path_exprs):
                self._add("MCP005", node, "MEDIUM", "A tool argument controls the path.")

        # ---- MCP009: outbound request with a caller-controlled URL ------------------
        if in_tool and not guard_url and last in HTTP_FUNCS and first is not None:
            mod = name.rsplit(".", 1)[0] if "." in name else ""
            if mod in HTTP_MODULES or mod in self.http_clients:
                if expr_tainted(first, tainted):
                    if _url_host_is_fixed(first):
                        self._add("MCP009", node, "LOW", "The host is fixed, so only the URL path or query is controlled.")
                    else:
                        self._add("MCP009", node, "MEDIUM", "A tool argument controls the URL.")

        # ---- MCP010: SQL built from caller input ------------------------------------
        if in_tool and last in SQL_METHODS and first is not None:
            built = (expr_tainted(first, tainted) and is_sql_interpolation(first)) or \
                (isinstance(first, ast.Name) and first.id in sql_built)
            if built:
                self._add("MCP010", node, "HIGH", "The query is built by string formatting.")
            elif isinstance(first, ast.Name) and first.id in params:
                self._add("MCP010", node, "MEDIUM", "The caller supplies the whole query.")

        # ---- MCP011: unsafe deserialization of caller input -------------------------
        if in_tool and first is not None and expr_tainted(first, tainted):
            if name in DESERIALIZERS or (name == "yaml.load" and not self._safe_yaml(node)):
                self._add("MCP011", node, "HIGH", "A tool argument is deserialized.")

        # ---- one hop into helper functions defined in this file ---------------------
        if in_tool and isinstance(node.func, ast.Name) and node.func.id in self.summaries:
            pnames, per_param = self.summaries[node.func.id]
            hostile = set()  # the helper's parameters that receive a tainted argument here
            for k, arg in enumerate(node.args):
                if isinstance(arg, ast.Starred):
                    hostile |= set(pnames[k:])
                elif expr_tainted(arg, tainted) and not is_constant_expr(arg):
                    hostile.add(pnames[k] if k < len(pnames) else "*")
            for kw in node.keywords:
                if kw.arg is None or (expr_tainted(kw.value, tainted) and not is_constant_expr(kw.value)):
                    hostile.add(kw.arg or "**")
            entries = []
            for p in hostile:
                entries += per_param.get(p, []) or (per_param.get("*", []) if p in ("*", "**") else [])
            for rule_id, severity in dict.fromkeys(entries):
                if (rule_id == "MCP005" and guard_path) or (rule_id == "MCP009" and guard_url):
                    continue  # the calling tool already checks the value
                self._add(rule_id, node, severity, f"Reached through helper `{node.func.id}`.")

        self.generic_visit(node)

    @staticmethod
    def _program_from_input(first: ast.AST, tainted: Set[str]) -> bool:
        if isinstance(first, (ast.List, ast.Tuple)):
            if not first.elts:
                return False
            head = first.elts[0]
            if expr_tainted(head, tainted):
                return True
            # ["sh", "-c", user_text] or [sys.executable, "-c", user_code]: a fixed program that runs
            # whatever it is handed
            program = ""
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                program = head.value.replace("\\", "/").rsplit("/", 1)[-1].lower()
                if program.endswith(".exe"):
                    program = program[:-4]
            elif dotted(head) == "sys.executable":
                program = "python"
            return program in INTERPRETERS and any(expr_tainted(e, tainted) for e in first.elts[1:])
        if isinstance(first, ast.Call):  # subprocess.run(x.split()) / shlex.split(x)
            if (isinstance(first.func, ast.Attribute) and first.func.attr == "split") \
                    or dotted(first.func) == "shlex.split":
                return expr_tainted(first, tainted)
        return False

    @staticmethod
    def _safe_yaml(call: ast.Call) -> bool:
        loaders = [k.value for k in call.keywords if k.arg == "Loader"] + call.args[1:2]
        return any(dotted(v).endswith(SAFE_YAML_LOADERS) for v in loaders)


def _summarize_helpers(tree: ast.Module, rel: str, lines: List[str], clients: Set[str]) -> Summaries:
    """For each plain function in the file: what happens if one parameter at a time is hostile?"""
    out: Summaries = {}
    for fn in tree.body:
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and not is_tool_func(fn):
            a = fn.args
            positional = [x.arg for x in a.posonlyargs + a.args]
            names = positional + [x.arg for x in a.kwonlyargs] + \
                ([a.vararg.arg] if a.vararg else []) + ([a.kwarg.arg] if a.kwarg else [])
            per_param: Dict[str, List[Tuple[str, str]]] = {}
            for p in names:
                if p in SKIP_PARAMS:
                    continue
                sub = _Visitor(rel, lines, clients)
                t = taint_set(fn, include_request=False, only={p})
                sub.stack.append((t, True, _has_guard(fn, GUARD_ATTRS), _has_guard(fn, URL_GUARDS),
                                  raw_params(fn) & {p}, sql_built_names(fn, t)))
                for stmt in fn.body:
                    sub.visit(stmt)
                if sub.findings:
                    per_param[p] = [(f.rule_id, f.severity) for f in sub.findings]
            if a.vararg and a.vararg.arg in per_param:
                per_param["*"] = per_param[a.vararg.arg]
            if per_param:
                out[fn.name] = (positional, per_param)
    return out


def analyze(rel: str, text: str) -> Optional[List[Finding]]:
    """Return findings, or None if the file cannot be parsed."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    lines = text.splitlines()
    clients = _http_clients(tree)
    global _CLEAN_FUNCS, _TOOL_NAMES
    _CLEAN_FUNCS = set()
    _TOOL_NAMES = _schema_tool_names(tree)
    helpers = [fn for fn in tree.body
               if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and not is_tool_func(fn)]
    for _ in range(5):  # a helper that only calls clean helpers is clean too: iterate to a fixpoint
        grown = {fn.name for fn in helpers if fn.name not in _CLEAN_FUNCS and not _returns_tainted(fn)}
        if not grown:
            break
        _CLEAN_FUNCS |= grown
    try:
        v = _Visitor(rel, lines, clients, _summarize_helpers(tree, rel, lines, clients))
        v.visit(tree)
        return v.findings
    finally:
        _CLEAN_FUNCS = set()
        _TOOL_NAMES = set()


def _returns_tainted(fn) -> bool:
    """Would the function's return value carry its inputs, if every parameter were hostile?"""
    tainted = taint_set(fn, include_request=False)
    return any(isinstance(n, ast.Return) and n.value is not None and expr_tainted(n.value, tainted)
               for n in ast.walk(fn))
