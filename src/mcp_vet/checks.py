"""File-level checks that need more than a single-line regex."""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import replace
from typing import List, Optional

from .models import Finding
from .rules import RULES, CODE_EXTS

TOOL_MARKERS = re.compile(
    r"(@\w+\.tool\b|[\"']/mcp(/|[\"'])|tools/call|\bserver\.tool\(|registerTool|@tool\b|setRequestHandler|CallToolRequestSchema|FastMCP)"
)
NET_TRANSPORT = re.compile(
    r"(transport\s*=\s*['\"](sse|streamable-http|http)['\"]"
    r"|SSEServerTransport|StreamableHTTPServerTransport|SseServerTransport"
    r"|sse_app\(|streamable_http_app\(|\bapp\.listen\(|\bFastAPI\(|\bFlask\(|uvicorn\.run\()"
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
MODULE_ANCHORED = re.compile(r"(import\.meta|__dirname|__filename|new URL\()")
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
    if has_guard:
        return []
    for read in FILE_READ.finditer(text):
        line = _line_of(text, read.start())
        src = text.splitlines()[line - 1]
        if MODULE_ANCHORED.search(src):
            continue  # path is relative to this module, not tool input
        f = _finding("MCP005", file, line, src,
                     "Unverified: this language has no taint analysis, so the path may be constant.")
        return [replace(f, severity="LOW")]
    return []


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


# --------------------------------------------------------------------- credentials (MCP012)
_CRED_NAME = r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)"
CRED_ASSIGN = re.compile(
    r"(?P<key>[\w.\-]*" + _CRED_NAME + r"[\w.\-]*)[\"']?\s*[:=]\s*(?P<q>[\"'])(?P<val>[^\"'\s]{8,})(?P=q)(?P<after>.*)",
    re.IGNORECASE)
# The password runs to the LAST "@" before the host, so an unescaped "@" inside it does not split it.
CRED_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://(?P<user>[^\s/:@\"'<>]+):(?P<val>[^\s/\"'<>]{4,})@(?P<host>[^\s/@\"'<>:?]+)")
BEARER = re.compile(r"\bBearer\s+(?P<val>[A-Za-z0-9._~+/=\-]{20,})")
JWT = re.compile(r"\b(?P<val>eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{2,}\.[A-Za-z0-9_\-]{2,})")
PLACEHOLDER = re.compile(
    r"(example|placeholder|dummy|sample|your[-_ ]|changeme|change[-_]me|xxxx|\*{3,}|redacted|replace|todo|"
    r"fixme|insert|enter[-_]|<.*>|\$|\{|\}|%\(|%s|\bnone\b|\bnull\b|undefined|process\.env|os\.environ|"
    r"getenv|secret[-_]here|password[-_]here|\bno[-_]?(key|token|auth|secret|password)\b|not[-_]needed|"
    r"keyless|unused|disabled|anonymous|\blocal\b)", re.IGNORECASE)
LABEL_WORDS = {"password", "passwd", "secret", "token", "apikey", "api_key", "api-key", "accesstoken",
               "authtoken", "privatekey", "clientsecret", "username", "string", "required"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"}
DEV_PASSWORDS = {"postgres", "password", "pass", "passwd", "pwd", "secret", "root", "admin", "guest",
                 "test", "testing", "dev", "ci", "demo", "user", "changeme", "mysql", "redis"}
CRED_EXTS = CODE_EXTS + (".json", ".yaml", ".yml", ".env", ".toml")
LOCK_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "poetry.lock",
              "composer.lock", "cargo.lock", "uv.lock", "pipfile.lock"}


def _looks_random(v: str) -> bool:
    """Real credentials are generated: a mix of digits, case or symbols, not a readable word."""
    if any(ord(c) > 127 for c in v):  # translated text ("Contraseña", "Schlüssel"); secrets are ASCII
        return False
    if v.startswith("__") or v.endswith("__"):  # a dunder constant, not a secret
        return False
    has_letter, has_digit = any(c.isalpha() for c in v), any(c.isdigit() for c in v)
    has_symbol = any(c in "!@#$%^&*" for c in v)
    inner_caps = sum(c.isupper() for c in v[1:])  # a Capitalised word has none; random strings do
    mixed_case = inner_caps >= 2 and sum(c.islower() for c in v) >= 2
    return (has_letter and has_digit and len(v) >= 8) or (mixed_case and len(v) >= 12) \
        or (has_symbol and (has_letter or has_digit) and len(v) >= 8)


# A key that says what the value is *about* rather than holding the secret itself.
NOT_THE_SECRET = re.compile(
    r"(encrypt|algorithm|algo|hash|method|policy|type|mode|format|scheme|length|prefix|suffix|header|"
    r"field|label|title|hint|placeholder|description|message|caption|help|dialog|tooltip|button|"
    r"env|file|path|url|dir|command|cmd)", re.IGNORECASE)
# Folders and files that hold translations, test tooling or deliberate fake secrets.
SKIP_CRED_PATH = re.compile(
    r"((^|/)(i18n|locales?|lang|languages?|translations?|l10n|messages|copy)(/|\.)|translated|"
    r"redact|scrub|sanitiz|secret[-_]?scan|credential[-_]?detect|"
    r"(vitest|jest|playwright|cypress)\.config|[/_.\-](regression|smoke|e2e|bench|benchmarks?)([/_.\-]|$)|benchmark|"
    r"(^|/)(fixtures?|mocks?|testdata|__snapshots__)/)", re.IGNORECASE)


def _credential_value(key: str, val: str) -> bool:
    """True if `val` looks like a real credential rather than a label, placeholder or reference."""
    low = val.lower()
    if PLACEHOLDER.search(val) or low in LABEL_WORDS or low == key.lower() or NOT_THE_SECRET.search(key):
        return False
    if "." in key and not any(c.isdigit() or c in "!@#$%^&*" for c in val):  # an i18n key: 'login.password'
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_]{4,}", val):  # the name of an environment variable, not its value
        return False
    if val.startswith(("http://", "https://", "/", "./", "../", "~")) or "\\" in val:
        return False
    if re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+)+", val):  # a dotted identifier, e.g. an i18n key
        return False
    return _looks_random(val)


def _mask(line: str, match, group: str = "val") -> str:
    v = match.group(group)
    return line.replace(v, v[:2] + "***REDACTED***", 1)


def check_credentials(file: str, text: str, ext: str, name: str) -> List[Finding]:
    low_path = file.lower()
    if ext not in CRED_EXTS or name.lower() in LOCK_FILES or SKIP_CRED_PATH.search(low_path) \
            or re.search(r"(example|sample|template)", name, re.IGNORECASE) \
            or ".github/" in low_path or re.search(r"(^|/)(docker-)?compose[^/]*\.ya?ml$", low_path):
        return []  # lock files list package names; CI and compose files hold throwaway dev credentials
    out: List[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000 or RULES["MCP003"].pattern.search(line):  # known formats are MCP003's
            continue
        hit = None
        m = CRED_ASSIGN.search(line)
        # A literal followed by `+` is only the prefix of a generated value ("tok_" + randomUUID()).
        if m and not m.group("after").lstrip().startswith("+") and _credential_value(m.group("key"), m.group("val")):
            hit, what = m, "A secret-named variable or key is assigned a literal value."
        if hit is None:
            m = CRED_URL.search(line)
            if m:
                user, pw, host = m.group("user"), m.group("val"), m.group("host").lower()
                if user.lower() not in ("user", "username", "usr", "login", "name") and pw != user \
                        and pw.lower() not in DEV_PASSWORDS and not PLACEHOLDER.search(pw) \
                        and host not in LOCAL_HOSTS and "." in host and _looks_random(pw):
                    hit, what = m, "A URL contains a username and password."
        if hit is None:
            m = BEARER.search(line)
            # A comment that explains the "Bearer <token>" header is documentation, not a secret.
            if m and not PLACEHOLDER.search(m.group("val")) and not line.lstrip().startswith(("//", "#", "*", "/*")):
                hit, what = m, "A bearer token is written into the code."
        if hit is None:
            m = JWT.search(line)
            if m:
                hit, what = m, "A JSON Web Token is written into the code."
        if hit is not None:
            out.append(_finding("MCP012", file, i, _mask(line, hit), what))
    return out


# --------------------------------------------------------------------- obfuscation (MCP013)
B64_STRING = re.compile(r"[\"']([A-Za-z0-9+/]{12,}={0,2})[\"']")
MIN_OBFUSCATED_STRINGS = 8


def _base64_text(s: str) -> bool:
    """True if the string is valid base64 that decodes to readable UTF-8 text."""
    if s.startswith("eyJ"):  # a JWT segment, not hidden text
        return False
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        txt = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return False
    if len(txt) < 6 or not any(c.isalpha() for c in txt):
        return False
    return sum(c.isprintable() or c in "\n\t" for c in txt) / len(txt) >= 0.95 \
        and (len(txt) >= 10 or any(c in txt for c in " ._/:"))


def check_obfuscation(file: str, text: str, ext: str) -> List[Finding]:
    if ext not in CODE_EXTS:
        return []
    lines = text.splitlines()
    hits = [(i, m.group(1)) for i, ln in enumerate(lines, 1) if len(ln) < 4000
            for m in B64_STRING.finditer(ln) if _base64_text(m.group(1))]
    distinct = {s for _, s in hits}
    if len(distinct) < MIN_OBFUSCATED_STRINGS:
        return []
    first = hits[0][0]
    return [_finding("MCP013", file, first, lines[first - 1],
                     f"{len(distinct)} distinct base64-encoded text strings in this file.")]


# --------------------------------------------------------------------- client config launchers (MCP014)
JS_RUNNERS = {"npx", "bunx", "pnpx"}
DOCKER_RUNNERS = {"docker", "podman"}

DOCKER_VALUED_FLAGS = {
    "-e", "--env", "--env-file",
    "-v", "--volume", "--mount",
    "-p", "--publish", "--expose",
    "-u", "--user",
    "-w", "--workdir",
    "--name",
    "--network", "--net",
    "--entrypoint",
    "--restart",
    "--platform",
    "-h", "--hostname",
    "-m", "--memory", "--cpus",
    "-l", "--label",
    "--add-host",
    "--device",
    "--log-driver",
    "--security-opt",
    "--cap-add", "--cap-drop",
    "--pull",
    "--ip", "--mac-address",
}


def _first_package_arg(args: List[str]) -> Optional[str]:
    """The package a runner is asked to fetch: the first argument that is not a flag."""
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in ("-p", "--package", "--from", "-c", "--call"):
            skip_next = a in ("-c", "--call")  # their value is a command, not the package
            if a in ("-p", "--package", "--from"):
                continue
        if a.startswith("-"):
            continue
        return a
    return None


def _first_docker_image(args: List[str]) -> Optional[str]:
    """The container image in a docker/podman run command: the first non-flag argument after run."""
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a.startswith("-"):
            if "=" not in a and a in DOCKER_VALUED_FLAGS:
                skip_next = True
            continue
        return a
    return None


def _spec_is_pinned(runner: str, spec: str) -> bool:
    if runner in DOCKER_RUNNERS:
        if "@" in spec:
            return True
        last = spec.split("/")[-1]
        if ":" in last:
            tag = last.split(":", 1)[1]
            return bool(tag) and tag != "latest"
        return False
    if runner in JS_RUNNERS or runner in ("pnpm", "yarn"):
        body = spec[1:] if spec.startswith("@") else spec  # "@scope/name@1.2.3"
        return "@" in body and not body.endswith("@latest") and not body.endswith("@*")
    return ("==" in spec or "@" in spec) and not spec.endswith(("@latest", "==latest"))


def _launch_specs(data) -> list:
    """(command, args) for every server entry found anywhere in a parsed JSON config."""
    found = []
    if isinstance(data, dict):
        cmd, args = data.get("command"), data.get("args")
        if isinstance(cmd, str) and isinstance(args, list):
            found.append((cmd, [str(a) for a in args]))
        for v in data.values():
            found += _launch_specs(v)
    elif isinstance(data, list):
        for v in data:
            found += _launch_specs(v)
    return found


def check_launch_config(file: str, text: str, ext: str) -> List[Finding]:
    if ext != ".json" or '"command"' not in text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out: List[Finding] = []
    for command, args in _launch_specs(data):
        runner = re.split(r"[\\/]", command)[-1].lower()
        for suffix in (".cmd", ".exe", ".bat"):
            if runner.endswith(suffix):
                runner = runner[: -len(suffix)]
        spec = None
        if runner in JS_RUNNERS:
            spec = _first_package_arg(args)
        elif runner in ("pnpm", "yarn") and args[:1] == ["dlx"]:
            spec = _first_package_arg(args[1:])
        elif runner == "uvx":
            spec = _first_package_arg(args)
        elif runner == "pipx" and args[:1] == ["run"]:
            spec = _first_package_arg(args[1:])
        elif runner in DOCKER_RUNNERS and args[:1] == ["run"]:
            spec = _first_docker_image(args[1:])
        if not spec or _spec_is_pinned(runner, spec):
            continue
        idx = text.find(spec)
        line = _line_of(text, idx) if idx >= 0 else 1
        msg = (f"`{runner}` runs `{spec}` with no pinned tag."
               if runner in DOCKER_RUNNERS
               else f"`{runner}` fetches `{spec}` with no version.")
        out.append(_finding("MCP014", file, line, f'"command": "{command}", "args": [... "{spec}" ...]',
                            msg))
    return out
