"""Scope-aware analysis for JavaScript and TypeScript MCP servers, with no dependencies.

A tokenizer (strings, template literals, comments, regex literals) feeds a small analyzer that
finds tool and route handlers, follows tool arguments through assignments, and reports the
same classes of problem as the Python analyzer: command execution, file access, outbound
requests, SQL built from input. It is not a full parser, so it favours missing a rare
construct over guessing: unparsable files return None and fall back to the older patterns.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from .models import Finding, severity_rank
from .rules import RULES

OPEN, CLOSE = {"(": ")", "[": "]", "{": "}"}, {")", "]", "}"}
KEYWORDS_BEFORE_REGEX = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
                         "void", "throw", "instanceof", "yield", "await"}
PUNCT3 = {"...", "===", "!==", "**=", "<<=", ">>=", ">>>", "??=", "&&=", "||="}
PUNCT2 = {"=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "+=", "-=", "*=", "/=", "%=",
          "++", "--", "**", "<<", ">>"}
NOT_CALLS = {"if", "for", "while", "switch", "catch", "return", "function", "typeof", "await",
             "super", "import", "require", "void", "delete", "throw", "yield", "constructor"}
SKIP_PARAMS = {"res", "response", "reply", "next", "server", "extra", "context", "ctx",
               "sendNotification", "signal", "done", "callback", "cb"}
TOOL_CALLS = {"tool", "registerTool", "addTool"}
ROUTE_NAMES = {"get", "post", "put", "delete", "patch", "all", "route"}
SAN = re.compile(r"(valid|sanit|safe|allow|escape|quote|normali[sz]e|confine|within|inside|jail|"
                 r"sandbox|assert|^basename$|^encodeURIComponent$|^parseInt$|^parseFloat$|^Number$|"
                 r"^Boolean$|^resolve_)", re.I)
VALIDATOR_RECEIVER = re.compile(r"(^[A-Z0-9_]+$|allow|valid|known|white|permit|safe|enum|registry|supported)", re.I)
SQL_WORDS = re.compile(r"\b(select|insert|update|delete|create|drop|alter|truncate|union|where|from|into|values)\b", re.I)
PATH_GUARD_IDS = {"startsWith", "relative", "realpath", "realpathSync", "isSubPath", "isInside",
                  "isWithin", "isPathInside", "isContained"}
URL_GUARD_IDS = {"hostname", "host", "allowedHosts", "allowlist", "allowList", "isPrivate",
                 "isPrivateIP", "ipaddr", "dns"}
FS_NAMES = {"readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile",
            "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync",
            "readdir", "readdirSync", "mkdir", "mkdirSync", "rename", "renameSync", "copyFile",
            "copyFileSync", "cp", "cpSync", "createReadStream", "createWriteStream", "open",
            "openSync", "truncate", "chmod", "symlink", "opendir", "readlink"}
FS_TWO_PATH = {"rename", "renameSync", "copyFile", "copyFileSync", "cp", "cpSync", "symlink"}
FS_ROOTS = {"fs", "fsp", "promises", "fse", "fsExtra"}
HTTP_ROOTS = {"axios", "got", "http", "https", "request", "needle", "superagent", "undici", "ky", "fetch"}
SQL_NAMES = {"query", "execute", "raw", "$queryRawUnsafe", "$executeRawUnsafe",
             "queryRawUnsafe", "executeRawUnsafe"}
SQL_DB_ROOTS = {"db", "database", "sqlite", "conn", "connection"}
SQL_DB_NAMES = {"exec", "run", "all", "get", "prepare"}
SPAWN_NAMES = {"spawn", "spawnSync", "execFile", "execFileSync", "fork", "execa", "execaSync",
               "execaCommand", "execaCommandSync"}
CP_MODULES = {"child_process", "node:child_process", "shelljs", "execa", "cross-spawn"}
FS_MODULES = {"fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra", "graceful-fs"}
# z.enum / z.number / z.string().uuid() ... constrain an input so it cannot carry a payload.
SAFE_ZOD = {"enum", "nativeEnum", "literal", "number", "int", "boolean", "bigint", "date",
            "datetime", "uuid", "cuid", "regex", "ip"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "powershell", "pwsh"}
CONTINUE_END = {"+", "-", "*", "/", "%", "=", "==", "===", "!=", "!==", "<", ">", "<=", ">=", "&&",
                "||", "??", "?", ":", ".", "?.", ",", "(", "[", "{", "=>", "...", "!", "&", "|",
                "^", "+=", "-=", "*=", "/=", "%="}
CONTINUE_START = {".", "?.", "+", "-", "*", "/", "%", "&&", "||", "??", "?", ":", ")", "]", "}",
                  ",", "=>", "==", "===", "!=", "!==", "<", ">", "<=", ">=", "in", "instanceof", "of"}


class Tok:
    __slots__ = ("kind", "text", "line", "exprs")

    def __init__(self, kind: str, text: str, line: int, exprs=None):
        self.kind, self.text, self.line, self.exprs = kind, text, line, exprs or []


# ------------------------------------------------------------------------------ tokenizer
def _template(src: str, i: int, line: int):
    n, j, lit, exprs, start = len(src), i + 1, [], [], line
    while j < n and src[j] != "`":
        c = src[j]
        if c == "\\":
            lit.append(src[j + 1:j + 2])
            j += 2
            continue
        if c == "$" and src.startswith("${", j):
            sub, k, line = _scan(src, j + 2, line, True)
            exprs.append(sub)
            lit.append(" ")
            j = k + 1
            continue
        if c == "\n":
            line += 1
        lit.append(c)
        j += 1
    return j + 1, line, Tok("tpl", "".join(lit), start, exprs)


def _scan(src: str, i: int, line: int, nested: bool):
    toks: List[Tok] = []
    n, depth = len(src), 0
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r\f\v﻿":
            i += 1
            continue
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            end = n if j < 0 else j + 2
            line += src.count("\n", i, end)
            i = end
            continue
        if c in "'\"":
            j, buf = i + 1, []
            while j < n and src[j] != c and src[j] != "\n":
                if src[j] == "\\":
                    buf.append(src[j + 1:j + 2])
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            toks.append(Tok("str", "".join(buf), line))
            i = j + 1
            continue
        if c == "`":
            i, line, tok = _template(src, i, line)
            toks.append(tok)
            continue
        if c.isalpha() or c in "_$":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            toks.append(Tok("id", src[i:j], line))
            i = j
            continue
        if c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            toks.append(Tok("num", src[i:j], line))
            i = j
            continue
        if nested:
            if c == "{":
                depth += 1
            elif c == "}":
                if depth == 0:
                    return toks, i, line
                depth -= 1
        if c == "/":
            prev = toks[-1] if toks else None
            regex_ok = prev is None or (prev.kind == "p" and prev.text not in CLOSE) or \
                (prev.kind == "id" and prev.text in KEYWORDS_BEFORE_REGEX)
            if regex_ok:
                j, in_class, closed = i + 1, False, False
                while j < n and src[j] != "\n":
                    ch = src[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "[":
                        in_class = True
                    elif ch == "]":
                        in_class = False
                    elif ch == "/" and not in_class:
                        closed = True
                        break
                    j += 1
                if closed:
                    j += 1
                    while j < n and src[j].isalpha():
                        j += 1
                    toks.append(Tok("re", src[i:j], line))
                    i = j
                    continue
        for size, table in ((3, PUNCT3), (2, PUNCT2)):
            if src[i:i + size] in table:
                toks.append(Tok("p", src[i:i + size], line))
                i += size
                break
        else:
            toks.append(Tok("p", c, line))
            i += 1
    return toks, i, line


def tokenize(src: str) -> List[Tok]:
    return _scan(src, 0, 1, False)[0]


# ------------------------------------------------------------------------------ token helpers
def _pairs(T: List[Tok]) -> Dict[int, int]:
    out, stack = {}, []
    for i, t in enumerate(T):
        if t.kind != "p":
            continue
        if t.text in OPEN:
            stack.append(i)
        elif t.text in CLOSE and stack:
            out[stack.pop()] = i
    return out


def _ids(T: List[Tok], lo: int, hi: int) -> Set[str]:
    return {t.text for t in T[lo:hi] if t.kind == "id"}


def _ids_deep(T: List[Tok], lo: int, hi: int) -> Set[str]:
    """Identifiers in T[lo:hi], including those inside template-literal expressions."""
    out: Set[str] = set()
    for t in T[lo:hi]:
        if t.kind == "id":
            out.add(t.text)
        elif t.kind == "tpl":
            for e in t.exprs:
                out |= _ids_deep(e, 0, len(e))
    return out


def _has_sql_literal(T: List[Tok], lo: int, hi: int) -> bool:
    return any(t.kind in ("str", "tpl") and SQL_WORDS.search(t.text) for t in T[lo:hi])


def expr_end(T: List[Tok], lo: int, hi: int, pairs: Dict[int, int]) -> int:
    """Index just past the expression that starts at lo (statement-ending heuristic)."""
    j = lo
    while j < hi:
        t = T[j]
        if t.kind == "p":
            if t.text in OPEN:
                j = pairs.get(j, hi) + 1
                continue
            if t.text in (";",) or t.text in CLOSE or t.text == ",":
                return j
        if j > lo and t.line > T[j - 1].line:
            if T[j - 1].text not in CONTINUE_END and t.text not in CONTINUE_START:
                return j
        j += 1
    return hi


def binding_names(T: List[Tok], lo: int, hi: int, pairs: Dict[int, int]) -> List[str]:
    names: List[str] = []
    i = lo
    while i < hi and T[i].kind == "id" and T[i].text in ("public", "private", "protected", "readonly",
                                                          "async", "const", "let", "var"):
        i += 1
    if i < hi and T[i].text == "...":
        i += 1
    if i >= hi:
        return names
    t = T[i]
    if t.kind == "id":
        return [t.text]
    if t.kind == "p" and t.text in ("{", "["):
        close = pairs.get(i, hi)
        j = i + 1
        while j < close:
            x = T[j]
            if x.kind == "p" and x.text in OPEN:
                end = pairs.get(j, close)
                if x.text in ("{", "[") and T[j - 1].text == ":":
                    names += binding_names(T, j, end + 1, pairs)
                j = end + 1
                continue
            if x.text == "=":  # default value: skip to the next comma
                j += 1
                while j < close and T[j].text != ",":
                    j = pairs.get(j, j) + 1 if (T[j].kind == "p" and T[j].text in OPEN) else j + 1
                continue
            if x.kind == "id":
                if j + 1 < close and T[j + 1].text == ":":
                    j += 2
                    continue
                names.append(x.text)
            j += 1
    return names


def split_args(T: List[Tok], lo: int, hi: int, pairs: Dict[int, int]) -> List[Tuple[int, int]]:
    out, start, j = [], lo, lo
    while j < hi:
        t = T[j]
        if t.kind == "p" and t.text in OPEN:
            j = pairs.get(j, hi) + 1
            continue
        if t.kind == "p" and t.text == ",":
            out.append((start, j))
            start = j + 1
        j += 1
    if start < hi:
        out.append((start, hi))
    return out


def parse_function(T: List[Tok], lo: int, hi: int, pairs: Dict[int, int]):
    """(param names, body_lo, body_hi) for an arrow or function expression in T[lo:hi]."""
    j, arrow, fn = lo, None, None
    while j < hi:
        t = T[j]
        if t.kind == "p" and t.text in OPEN:
            j = pairs.get(j, hi) + 1
            continue
        if t.text == "=>":
            arrow = j
            break
        if t.kind == "id" and t.text == "function":
            fn = j
            break
        j += 1
    if arrow is not None:
        p = lo
        while p < arrow and T[p].text == "async":
            p += 1
        if p >= arrow:
            return None
        if T[p].text == "(":
            pc = pairs.get(p, arrow)
            params: List[str] = []
            for a, b in split_args(T, p + 1, pc, pairs):
                params += binding_names(T, a, b, pairs)
        else:
            params = [T[p].text] if T[p].kind == "id" else []
        b = arrow + 1
        if b < hi and T[b].text == "{":
            return params, b + 1, pairs.get(b, hi)
        return params, b, hi
    if fn is not None:
        p = fn + 1
        while p < hi and T[p].text != "(":
            p += 1
        if p >= hi:
            return None
        pc = pairs.get(p, hi)
        params = []
        for a, b in split_args(T, p + 1, pc, pairs):
            params += binding_names(T, a, b, pairs)
        b = pc + 1
        while b < hi and T[b].text != "{":
            b += 1
        if b < hi:
            return params, b + 1, pairs.get(b, hi)
    return None


# ------------------------------------------------------------------------------ analysis
class Ctx:
    def __init__(self, rel: str, lines: List[str], T: List[Tok], pairs: Dict[int, int]):
        self.rel, self.lines, self.T, self.pairs = rel, lines, T, pairs
        strs = {t.text for t in T if t.kind == "str"}
        self.imports_cp = any("child_process" in s for s in strs)
        self.imports_fs = bool(strs & {"fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra"})
        self.defs: Dict[str, tuple] = {}
        self.simple: Dict[str, bool] = {}   # helper has plain positional parameters (no destructuring)
        # helper name -> {parameter index -> findings if that parameter is hostile}; -1 = any argument
        self.summaries: Dict[str, Dict[int, List[Tuple[str, str]]]] = {}
        self.modmap: Dict[str, str] = {}                   # local name -> module (default / namespace)
        self.aliases: Dict[str, Tuple[str, str]] = {}      # local name -> (original name, module)
        _scan_imports(self)


def _scan_imports(ctx: "Ctx") -> None:
    """Track `import {a as b} from 'm'`, `const {a: b} = require('m')`, `promisify(a)`."""
    T, pairs, n = ctx.T, ctx.pairs, len(ctx.T)
    for i, t in enumerate(T):
        if t.kind != "id":
            continue
        if t.text == "import":
            frm, j = None, i + 1
            while j < n and j < i + 80 and T[j].text != ";":
                if T[j].kind == "id" and T[j].text == "from" and j + 1 < n and T[j + 1].kind == "str":
                    frm = j
                    break
                j += 1
            if frm is None:
                continue
            module, k = T[frm + 1].text, i + 1
            while k < frm:
                x = T[k]
                if x.kind == "p" and x.text == "{":
                    close, m = pairs.get(k, frm), k + 1
                    while m < close:
                        if T[m].kind == "id" and T[m].text != "type":
                            if m + 2 < close + 1 and T[m + 1].text == "as" and T[m + 2].kind == "id":
                                ctx.aliases[T[m + 2].text] = (T[m].text, module)
                                m += 3
                                continue
                            ctx.aliases[T[m].text] = (T[m].text, module)
                        m += 1
                    k = close + 1
                    continue
                if x.kind == "id" and x.text not in ("type", "as", "from"):
                    ctx.modmap[x.text] = module  # default import or `* as ns`
                k += 1
        elif t.text in ("const", "let", "var") and i + 1 < n:
            eq, k = None, i + 1
            while k < min(n, i + 60):
                if T[k].text == "=":
                    eq = k
                    break
                k = pairs.get(k, k) + 1 if (T[k].kind == "p" and T[k].text in OPEN) else k + 1
            if eq is None or eq + 3 >= n:
                continue
            local = T[i + 1]
            if T[eq + 1].text == "require" and T[eq + 2].text == "(" and T[eq + 3].kind == "str":
                module = T[eq + 3].text
                if local.kind == "id":
                    ctx.modmap[local.text] = module
                elif local.text == "{":
                    close, m = pairs.get(i + 1, eq), i + 2
                    while m < close:
                        if T[m].kind == "id":
                            if m + 2 <= close and T[m + 1].text == ":" and T[m + 2].kind == "id":
                                ctx.aliases[T[m + 2].text] = (T[m].text, module)
                                m += 3
                                continue
                            ctx.aliases[T[m].text] = (T[m].text, module)
                        m += 1
            elif local.kind == "id":
                for p in range(eq + 1, min(n - 2, eq + 4)):
                    if T[p].text == "promisify" and T[p + 1].text == "(":
                        close = pairs.get(p + 1, p + 2)
                        inner = [x for x in T[p + 2:close] if x.kind == "id"]
                        required = next((x.text for x in T[p + 2:close] if x.kind == "str"), "")
                        if inner:
                            origin = inner[-1].text
                            if required:  # promisify(require('child_process').exec)
                                ctx.aliases[local.text] = (origin, required)
                            elif len(inner) == 1 and origin in ctx.aliases:
                                ctx.aliases[local.text] = ctx.aliases[origin]
                            elif len(inner) > 1 and inner[0].text in ctx.modmap:
                                ctx.aliases[local.text] = (origin, ctx.modmap[inner[0].text])
                            elif len(inner) > 1 and inner[0].text in ("fs", "fsp"):
                                ctx.aliases[local.text] = (origin, "fs")
                            else:
                                ctx.aliases[local.text] = (origin, "")
                        break


CMP_OPS = {"===", "!==", "==", "!="}
# Local helpers whose return value does not carry their inputs (set per file by analyze()).
_CLEAN_RETURNS: Set[str] = set()


def _tainted(T, lo, hi, tainted: Set[str]) -> bool:
    """True if the value of T[lo:hi] can carry tool input.

    Three refinements keep the common safe patterns quiet: a ternary's value comes only from
    its branches, an equality test yields a boolean, and indexing an untainted object with a
    tainted key (`ORDERS[args.sort]`) yields a value the caller does not control.
    """
    depth, q = 0, None
    for j in range(lo, hi):
        t = T[j]
        if t.kind == "p":
            if t.text in OPEN:
                depth += 1
            elif t.text in CLOSE:
                depth -= 1
            elif depth == 0 and t.text == "?":
                q = j
                break
    if q is not None:
        nest, depth, colon = 0, 0, None
        for j in range(q + 1, hi):
            t = T[j]
            if t.kind != "p":
                continue
            if t.text in OPEN:
                depth += 1
            elif t.text in CLOSE:
                depth -= 1
            elif depth == 0 and t.text == "?":
                nest += 1
            elif depth == 0 and t.text == ":":
                if nest == 0:
                    colon = j
                    break
                nest -= 1
        if colon is not None:
            return _tainted(T, q + 1, colon, tainted) or _tainted(T, colon + 1, hi, tainted)
    depth = 0
    for j in range(lo, hi):
        t = T[j]
        if t.kind == "p":
            if t.text in OPEN:
                depth += 1
            elif t.text in CLOSE:
                depth -= 1
            elif depth == 0 and t.text in CMP_OPS:
                return False
        elif t.kind == "id" and depth == 0 and t.text == "instanceof":
            return False
    j = lo
    while j < hi:
        t = T[j]
        if t.kind == "p" and t.text == "[" and j > lo \
                and (T[j - 1].kind == "id" or T[j - 1].text in (")", "]")) \
                and T[j - 1].text not in KEYWORDS_BEFORE_REGEX:
            j = _skip_call(T, j, hi)  # index expression: the key does not taint the result
            continue
        if t.kind == "id":
            bare = j == lo or T[j - 1].text not in (".", "?.")
            if j + 1 < hi and T[j + 1].text == "(" and (SAN.search(t.text) or (bare and t.text in _CLEAN_RETURNS)):
                end = _skip_call(T, j + 1, hi)
                j = end
                continue
            if t.text in tainted and j + 3 < hi and T[j + 1].text == "." and T[j + 2].text == "map" \
                    and T[j + 3].text == "(" and bare:
                mc = _skip_call(T, j + 3, hi)
                if _callback_ignores_element(T, j + 4, mc - 1, tainted):
                    j = mc  # items.map(() => '?'): the result does not depend on the items
                    continue
            prev = T[j - 1].text if j > lo else ""
            if t.text in tainted and prev not in (".", "?.") \
                    and not (j + 1 < hi and T[j + 1].text == ":" and prev in ("{", ",")):
                return True
        elif t.kind == "str" and j + 3 < hi and T[j + 1].text == "." and T[j + 2].text == "repeat" \
                and T[j + 3].text == "(":
            j = _skip_call(T, j + 3, hi)  # '?'.repeat(n): a constant string whatever n is
            continue
        elif t.kind == "tpl":
            if any(_tainted(e, 0, len(e), tainted) for e in t.exprs):
                return True
        j += 1
    return False


def _callback_ignores_element(T: List[Tok], lo: int, hi: int, tainted: Set[str]) -> bool:
    """`(_, i) => ...` / `() => '?'`: an arrow whose result never uses the array element."""
    arrow = next((k for k in range(lo, hi) if T[k].text == "=>"), None)
    if arrow is None or arrow + 1 >= hi or T[arrow + 1].text == "{":
        return False
    names = [x.text for x in T[lo:arrow] if x.kind == "id"]
    # Clean if the body stays clean even when the element is hostile: a constant ('?'), an index
    # (`$${i + 1}`), or the element passed through a sanitizer (`id(f.column)`).
    return not _tainted(T, arrow + 1, hi, tainted | set(names[:1]))


def _sanitizer_aliases(ctx: "Ctx") -> Set[str]:
    """`const id = pg.escapeIdentifier;` or `import { escapeId as q }` name a sanitizer differently."""
    T, out = ctx.T, set()
    for local, (orig, _module) in ctx.aliases.items():
        if SAN.search(orig):
            out.add(local)
    for i, t in enumerate(T):
        if t.kind == "id" and t.text in ("const", "let", "var") and i + 3 < len(T) \
                and T[i + 1].kind == "id" and T[i + 2].text == "=":
            k, last = i + 3, None
            while k < len(T) and T[k].kind == "id":
                last = T[k].text
                if k + 1 < len(T) and T[k + 1].text == ".":
                    k += 2
                else:
                    k += 1
                    break
            if last and SAN.search(last) and not (k < len(T) and T[k].text == "("):
                out.add(T[i + 1].text)
    return out


_PAIR_CACHE: Dict[int, Dict[int, int]] = {}


def _skip_call(T, open_idx, hi) -> int:
    depth, j = 0, open_idx
    while j < hi:
        if T[j].kind == "p" and T[j].text in OPEN:
            depth += 1
        elif T[j].kind == "p" and T[j].text in CLOSE:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return hi


def _constant(T, lo, hi) -> bool:
    j = lo
    while j < hi:
        t = T[j]
        if t.kind == "id":
            if j + 1 < hi and T[j + 1].text == "(" and SAN.search(t.text):
                j = _skip_call(T, j + 1, hi)
                continue
            if t.text not in ("true", "false", "null", "undefined"):
                return False
        elif t.kind == "tpl" and t.exprs:
            return False
        j += 1
    return True


def _propagate(ctx: Ctx, lo: int, hi: int, tainted: Set[str], validated: Optional[Set[str]] = None) -> Set[str]:
    """Returns names holding a SQL string built from tainted pieces; grows `tainted` in place."""
    T, pairs = ctx.T, ctx.pairs
    sql_built: Set[str] = set()
    val = validated or set()  # names checked against an allowlist never become tainted
    for _ in range(3):
        i = lo
        while i < hi:
            t = T[i]
            if t.kind == "id" and t.text in ("const", "let", "var"):
                k = i + 1
                while k < hi and T[k].text not in ("=", ";", "of", "in"):
                    k = pairs.get(k, k) + 1 if (T[k].kind == "p" and T[k].text in OPEN) else k + 1
                if k < hi and T[k].text in ("=", "of", "in"):
                    names = binding_names(T, i + 1, k, pairs)
                    e = expr_end(T, k + 1, hi, pairs)
                    if _tainted(T, k + 1, e, tainted):
                        tainted |= set(names) - val
                        if T[k].text == "=" and _has_sql_literal(T, k + 1, e):
                            sql_built |= set(names)
            elif t.kind == "id" and i + 1 < hi and T[i + 1].text in ("=", "+=") \
                    and (i == lo or T[i - 1].text not in (".", "?.")):
                e = expr_end(T, i + 2, hi, pairs)
                if _tainted(T, i + 2, e, tainted) and t.text not in val:
                    tainted.add(t.text)
                    if _has_sql_literal(T, i + 2, e):
                        sql_built.add(t.text)
            i += 1
    return sql_built


def _validated(ctx: Ctx, lo: int, hi: int) -> Set[str]:
    """x is validated by `ALLOWED.includes(x)`, `allowed.has(x)` or `x in ALLOWED`."""
    T, out = ctx.T, set()
    for j in range(lo, hi - 2):
        t = T[j]
        if t.kind == "id" and t.text in ("includes", "has", "indexOf") and T[j + 1].text == "(" \
                and T[j + 2].kind == "id" and j + 3 < hi and T[j + 3].text == ")" \
                and j >= 2 and T[j - 1].text in (".", "?.") and T[j - 2].kind == "id" \
                and VALIDATOR_RECEIVER.search(T[j - 2].text):
            out.add(T[j + 2].text)
        if t.kind == "id" and T[j + 1].kind == "id" and T[j + 1].text == "in" and j + 2 < hi \
                and T[j + 2].kind == "id" and VALIDATOR_RECEIVER.search(T[j + 2].text):
            out.add(t.text)
    return out


class Body:
    def __init__(self, ctx: Ctx, lo: int, hi: int, tainted: Set[str], in_tool: bool,
                 skip: Optional[List[Tuple[int, int]]] = None, hop: bool = True,
                 extra_validated: Optional[Set[str]] = None):
        self.ctx, self.lo, self.hi, self.in_tool, self.skip, self.hop = ctx, lo, hi, in_tool, skip or [], hop
        T = ctx.T
        self.raw_params = set(tainted)
        self.validated = _validated(ctx, lo, hi) | (extra_validated or set())
        self.tainted = set(tainted) - self.validated
        self.sql_built = _propagate(ctx, lo, hi, self.tainted, self.validated)
        ids = _ids(T, lo, hi)
        # `x.includes('..')` only guards x, so the receiver must be one of the tool's inputs.
        self.dotdot_names = {
            T[j - 2].text for j in range(lo + 2, max(lo + 2, hi - 2))
            if T[j].text == "includes" and T[j + 1].text == "(" and T[j + 2].kind == "str"
            and ".." in T[j + 2].text and T[j - 1].text in (".", "?.") and T[j - 2].kind == "id"}
        self.guard_path = bool(ids & PATH_GUARD_IDS)
        self.guard_url = bool(ids & URL_GUARD_IDS)
        self.findings: List[Finding] = []

    def _add(self, rule_id: str, line: int, severity: str, extra: str = ""):
        r = RULES[rule_id]
        lines = self.ctx.lines
        snippet = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
        self.findings.append(Finding(r.id, r.title, severity, self.ctx.rel, line, snippet,
                                     r.message + (f" {extra}" if extra else ""), r.remediation))

    def _t(self, lo, hi) -> bool:
        return _tainted(self.ctx.T, lo, hi, self.tainted)

    def _validated_only(self, rng) -> bool:
        """The expression uses a tool input that was checked against an allowlist."""
        return bool(_ids_deep(self.ctx.T, rng[0], rng[1]) & self.validated)

    def _dotdot_guarded(self, picked) -> bool:
        """A `x.includes('..')` check guards x. Derived variables get the benefit of the doubt."""
        if not self.dotdot_names:
            return False
        T = self.ctx.T
        used = {name for a, b in picked for name in _ids_deep(T, a, b) if name in self.tainted}
        return (used & self.raw_params) <= self.dotdot_names

    def _definition(self, name_idx: int, close: int, args) -> bool:
        T = self.ctx.T
        nxt = T[close + 1].text if close + 1 < len(T) else ""
        if nxt == ":" and any(T[k].text == ":" for a, b in args for k in range(a, min(a + 3, b))):
            return True  # typed parameter list: a method signature
        if nxt == "{":
            prev = T[name_idx - 1].text if name_idx else ";"
            return prev in (";", "}", "{", "async", "static", "public", "private", "protected", "get", "set") \
                or T[name_idx - 1].line < T[name_idx].line
        return False

    def run(self) -> List[Finding]:
        ctx, T, pairs = self.ctx, self.ctx.T, self.ctx.pairs
        for i in range(self.lo, self.hi):
            t = T[i]
            if t.kind != "id" or i + 1 >= len(T) or T[i + 1].text != "(" or t.text in NOT_CALLS:
                continue
            if any(a <= i < b for a, b in self.skip):
                continue
            if i > 0 and T[i - 1].text == "function":
                continue
            close = pairs.get(i + 1, self.hi)
            args = split_args(T, i + 2, close, pairs)
            if self._definition(i, close, args):
                continue
            parts, j = [t.text], i - 1
            while j >= 1 and T[j].text in (".", "?.") and T[j - 1].kind == "id":
                parts.insert(0, T[j - 1].text)
                j -= 2
            if len(parts) == 1 and i > 0 and T[i - 1].text in (".", "?."):
                parts.insert(0, "?")  # method call on something unnameable: /re/.exec(x), f().exec(x)
            name, root, chain = t.text, parts[0], ".".join(parts)
            module = ""
            if "." not in chain and name in ctx.aliases:      # import { exec as run } / promisify(exec)
                name, module = ctx.aliases[name]
            elif "." in chain and root in ctx.modmap:         # import * as cp / const shell = require('shelljs')
                module = ctx.modmap[root]
            is_new = i > 0 and T[i - 1].text == "new"
            line = t.line
            first = args[0] if args else None
            first_tainted = bool(first) and self._t(*first)
            first_const = first is None or _constant(T, *first)
            any_tainted = any(self._t(a, b) and not _constant(T, a, b) for a, b in args)

            # ---- MCP001 ----
            # `re.exec(text)` and `router.exec(...)` are not child_process: the call must come from it.
            exec_ok = "child_process" in chain or module in CP_MODULES
            if name in ("exec", "execSync") and exec_ok and not is_new and first is not None:
                if first_tainted:
                    self._add("MCP001", line, "HIGH", "A tool argument reaches this call.")
                elif not first_const and not (self.in_tool and self._validated_only(first)):
                    self._add("MCP001", line, "MEDIUM", "The argument is not a constant.")
            elif name in SPAWN_NAMES and exec_ok and first is not None:
                shell = any(T[k].text == "shell" and k + 2 < close and T[k + 1].text == ":" and T[k + 2].text == "true"
                            for k in range(i + 2, close))
                program = T[first[0]].text.replace("\\", "/").rsplit("/", 1)[-1].lower() \
                    if first_const and T[first[0]].kind == "str" else ""
                if program.endswith(".exe"):
                    program = program[:-4]
                if first_tainted:
                    self._add("MCP001", line, "HIGH", "A tool argument chooses the program to run.")
                elif (shell or program in SHELLS) and any_tainted:
                    self._add("MCP001", line, "HIGH", "A tool argument reaches a shell command.")
            elif (name == "eval" and not is_new and "." not in chain) or (is_new and name == "Function") \
                    or (name in ("runInNewContext", "runInThisContext", "runInContext") and root in ("vm", "vm2")):
                if first is not None and not first_const:
                    if first_tainted or (is_new and any_tainted):
                        self._add("MCP001", line, "HIGH", "A tool argument is evaluated as code.")
                    elif not (self.in_tool and self._validated_only(first)):
                        self._add("MCP001", line, "MEDIUM", "Dynamic code with a non-constant argument.")

            if self.in_tool:
                # ---- MCP005 ----
                fs_call = name in FS_NAMES and (root in FS_ROOTS or module in FS_MODULES
                                                or (ctx.imports_fs and "." not in chain))
                send = name in ("sendFile", "download") and root in ("res", "response", "reply")
                if (fs_call or send) and not self.guard_path:
                    picked = args[:2] if name in FS_TWO_PATH else args[:1]
                    has_root_option = send and any(T[k].text == "root" for k in range(i + 2, close))
                    if not has_root_option and not self._dotdot_guarded(picked) \
                            and any(self._t(a, b) and not _constant(T, a, b) for a, b in picked):
                        self._add("MCP005", line, "MEDIUM", "A tool argument controls the path.")
                # ---- MCP009 ----
                http = (name in ("fetch", "got", "axios", "request", "needle", "ky") and "." not in chain) or \
                    (root in HTTP_ROOTS and name in ("get", "post", "put", "delete", "patch", "head",
                                                      "request", "fetch", "stream"))
                if http and not self.guard_url and first_tainted and not first_const:
                    self._add("MCP009", line, "MEDIUM", "A tool argument controls the URL.")
                # ---- MCP010 ----
                sql = name in SQL_NAMES or (name in SQL_DB_NAMES and root in SQL_DB_ROOTS)
                if sql and first is not None:
                    a, b = first
                    interpolated = self._t(a, b) and _has_sql_literal(T, a, b) and \
                        (any(T[k].kind == "tpl" and T[k].exprs for k in range(a, b)) or
                         any(T[k].text == "+" for k in range(a, b)))
                    built_var = b - a == 1 and T[a].kind == "id" and T[a].text in self.sql_built
                    if interpolated or built_var:
                        self._add("MCP010", line, "HIGH", "The query is built by string formatting.")
                    elif b - a == 1 and T[a].kind == "id" and T[a].text in self.raw_params \
                            and T[a].text in self.tainted:
                        self._add("MCP010", line, "MEDIUM", "The caller supplies the whole query.")
                # ---- MCP011 ----
                if name in ("unserialize", "deserialize") and first_tainted:
                    self._add("MCP011", line, "HIGH", "A tool argument is deserialized.")

            # ---- one hop into helpers defined in this file ----
            if self.hop and self.in_tool and "." not in chain and name in ctx.summaries and any_tainted:
                summary = ctx.summaries[name]
                if -1 in summary:
                    entries = summary[-1]
                else:  # only the parameters whose arguments are tainted here
                    entries = []
                    for k, (a, b) in enumerate(args):
                        if self._t(a, b) and not _constant(T, a, b):
                            entries += summary.get(k, [])
                for rule_id, sev in dict.fromkeys(entries):
                    if (rule_id == "MCP005" and self.guard_path) or (rule_id == "MCP009" and self.guard_url):
                        continue
                    self._add(rule_id, line, sev, f"Reached through helper `{name}`.")
        return self.findings


def _returns_tainted(ctx: Ctx, params: List[str], lo: int, hi: int) -> bool:
    """Would the function's return value carry its inputs, if every parameter were hostile?"""
    tainted = {p for p in params if p not in SKIP_PARAMS}
    if not tainted:
        return False
    T, pairs = ctx.T, ctx.pairs
    _propagate(ctx, lo, hi, tainted)
    if not (lo > 0 and T[lo - 1].text == "{"):  # expression-bodied arrow function
        return _tainted(T, lo, hi, tainted)
    for i in range(lo, hi):
        if T[i].kind == "id" and T[i].text == "return":
            if _tainted(T, i + 1, expr_end(T, i + 1, hi, pairs), tainted):
                return True
    return False


def _plain_params(T: List[Tok], pairs: Dict[int, int], open_idx: int) -> bool:
    """True if the parameter list at open_idx has no destructuring, rest or default values."""
    close = pairs.get(open_idx, open_idx)
    return not any(T[k].text in ("{", "[", "...", "=") for k in range(open_idx + 1, close))


def _find_defs(ctx: Ctx):
    """Named functions: `function f(...) {}` and `const f = (...) => {}` / `function () {}`."""
    T, pairs = ctx.T, ctx.pairs
    for i, t in enumerate(T):
        if t.kind != "id":
            continue
        if t.text == "function" and i + 2 < len(T) and T[i + 1].kind == "id" and T[i + 2].text == "(":
            parsed = parse_function(T, i, min(len(T), pairs.get(i + 2, len(T)) + 200), pairs)
            if parsed:
                ctx.defs.setdefault(T[i + 1].text, parsed)
                ctx.simple.setdefault(T[i + 1].text, _plain_params(T, pairs, i + 2))
        elif t.text in ("const", "let", "var") and i + 3 < len(T) and T[i + 1].kind == "id" \
                and T[i + 2].text == "=":
            e = expr_end(T, i + 3, len(T), pairs)
            parsed = parse_function(T, i + 3, e, pairs)
            if parsed:
                ctx.defs.setdefault(T[i + 1].text, parsed)
                k = i + 3
                while k < e and T[k].text in ("async", "function") or (k < e and T[k].kind == "id" and T[k - 1].text == "function"):
                    k += 1
                if k < e and T[k].text == "(":
                    ctx.simple.setdefault(T[i + 1].text, _plain_params(T, pairs, k))
                else:
                    ctx.simple.setdefault(T[i + 1].text, k < e and T[k].kind == "id")


def _schema_safe_names(T: List[Tok], ranges, pairs: Dict[int, int]) -> Set[str]:
    """Keys whose zod type constrains the value (enum, number, uuid, regex ...)."""
    out: Set[str] = set()
    for a, b in ranges:
        for j in range(a, b - 2):
            if T[j].kind == "id" and T[j + 1].text == ":" and T[j + 2].kind == "id":
                k = j + 2
                while k < b and not (T[k].kind == "p" and T[k].text == ","):
                    k = pairs.get(k, k) + 1 if (T[k].kind == "p" and T[k].text in OPEN) else k + 1
                ids = _ids_deep(T, j + 2, k)
                if ids & {"z", "zod"} and ids & SAFE_ZOD:
                    out.add(T[j].text)
    return out


def _handlers(ctx: Ctx):
    """Yield (params, body_lo, body_hi, schema-constrained names) for tool and route handlers."""
    T, pairs = ctx.T, ctx.pairs
    for i, t in enumerate(T):
        if t.kind != "id" or i + 1 >= len(T) or T[i + 1].text != "(":
            continue
        dotted = i > 0 and T[i - 1].text in (".", "?.")
        close = pairs.get(i + 1)
        if close is None:
            continue
        args = split_args(T, i + 2, close, pairs)
        if not args:
            continue
        is_tool = t.text in TOOL_CALLS and dotted
        is_set = t.text == "setRequestHandler" and dotted
        a0 = args[0]
        is_route = t.text in ROUTE_NAMES and dotted and a0[1] - a0[0] >= 1 and \
            T[a0[0]].kind in ("str", "tpl") and T[a0[0]].text.startswith("/")
        if not (is_tool or is_set or is_route):
            continue
        for idx in range(len(args) - 1, -1, -1):
            a, b = args[idx]
            parsed = parse_function(T, a, b, pairs)
            if parsed is None and b - a == 1 and T[a].kind == "id" and T[a].text in ctx.defs:
                parsed = ctx.defs[T[a].text]
            if parsed:
                params, lo, hi = parsed
                names = {p for p in params if p not in SKIP_PARAMS}
                if is_route or is_set:
                    names |= {"req", "request"}
                safe = _schema_safe_names(T, args[:idx], pairs) if is_tool else set()
                yield names, lo, hi, safe
                break


def analyze(rel: str, text: str) -> Optional[List[Finding]]:
    """Findings for a JS/TS file, or None if it cannot be tokenized sensibly."""
    if len(text) > 600_000:
        return None
    try:
        T = tokenize(text)
    except (RecursionError, IndexError):
        return None
    if not T:
        return []
    ctx = Ctx(rel, text.splitlines(), T, _pairs(T))
    _find_defs(ctx)
    global _CLEAN_RETURNS
    _CLEAN_RETURNS = {name for name, (params, lo, hi) in ctx.defs.items()
                      if not _returns_tainted(ctx, params, lo, hi)} | _sanitizer_aliases(ctx)

    handlers = list(_handlers(ctx))
    handler_ranges = [(lo, hi) for _, lo, hi, _ in handlers]
    handler_bodies = {(lo, hi) for _, lo, hi, _ in handlers}

    # Summaries: what would a plain helper do if every parameter were hostile?
    for name, (params, lo, hi) in ctx.defs.items():
        if (lo, hi) in handler_bodies:
            continue
        if ctx.simple.get(name):
            per: Dict[int, List[Tuple[str, str]]] = {}
            for k, p in enumerate(params):
                if p in SKIP_PARAMS:
                    continue
                found = Body(ctx, lo, hi, {p}, True, hop=False).run()
                if found:
                    per[k] = [(f.rule_id, f.severity) for f in found]
            if per:
                ctx.summaries[name] = per
        else:
            found = Body(ctx, lo, hi, {p for p in params if p not in SKIP_PARAMS}, True, hop=False).run()
            if found:
                ctx.summaries[name] = {-1: [(f.rule_id, f.severity) for f in found]}

    findings: List[Finding] = []
    for names, lo, hi, safe in handlers:
        findings += Body(ctx, lo, hi, names, True, extra_validated=safe).run()
    findings += Body(ctx, 0, len(T), set(), False, skip=handler_ranges).run()

    best: Dict[Tuple[str, int], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.line)
        if key not in best or severity_rank(f.severity) > severity_rank(best[key].severity):
            best[key] = f
    return list(best.values())
