from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Optional

from . import checks, pyast
from .models import Finding, ScanResult, severity_rank
from .rules import RULES, HIDDEN_CHARS, HIDDEN_STRICT, ZW_RUN, PROSE_EXTS, CODE_EXTS

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             ".tox", ".mypy_cache", ".pytest_cache", "site-packages"}
SCAN_EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".json", ".yaml", ".yml",
             ".toml", ".md", ".txt", ".env"}
MAX_BYTES = 1_000_000
BOM = chr(0xFEFF)
COMMENT_RE = re.compile(r"\s*(//|/\*|\*|#)")
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e"}
TEST_FILE_RE = re.compile(r"(^test_.*\.py$|_test\.py$|\.(test|spec)\.(js|mjs|cjs|ts|tsx)$|^conftest\.py$)")
IGNORE_RE = re.compile(r"mcp-vet:\s*ignore(?:\s+((?:MCP\d{3}[,\s]*)+))?", re.IGNORECASE)


def _iter_files(root: Path, include_tests: bool = False):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                       and (include_tests or d.lower() not in TEST_DIRS)]
        for name in filenames:
            if not include_tests and TEST_FILE_RE.search(name):
                continue
            p = Path(dirpath) / name
            if p.suffix.lower() in SCAN_EXTS or name.lower().startswith(".env"):
                yield p


def _suppressed(line: str, rule_id: str) -> bool:
    m = IGNORE_RE.search(line)
    if not m:
        return False
    ids = m.group(1)
    return True if not ids else rule_id in re.findall(r"MCP\d{3}", ids)


def _redact(line: str, rule_pattern: re.Pattern) -> str:
    return rule_pattern.sub(lambda m: m.group(0)[:4] + "***REDACTED***", line)


class ProjectContext:
    """Facts gathered from every file, so one file's checks can see the others."""

    def __init__(self, has_auth: bool = False, has_guard: bool = False):
        self.has_auth = has_auth
        self.has_guard = has_guard


def build_context(files: List[tuple]) -> ProjectContext:
    has_auth = has_guard = False
    for name, text in files:
        if Path(name).suffix.lower() in CODE_EXTS:
            has_auth = has_auth or checks.AUTH_HINT.search(text) is not None
            has_guard = has_guard or checks.PATH_GUARD.search(text) is not None
    return ProjectContext(has_auth, has_guard)


def scan_text(rel: str, text: str, name: str, ctx: Optional[ProjectContext] = None) -> List[Finding]:
    ext = Path(name).suffix.lower()
    lines = text.splitlines()
    findings: List[Finding] = []

    # Python gets AST analysis (taint-aware). If parsing fails we fall back to regexes.
    ast_findings = pyast.analyze(rel, text) if ext == ".py" else None
    skip_rules = {"MCP001"} if ast_findings is not None else set()
    if ast_findings:
        findings.extend(ast_findings)

    for rule in RULES.values():
        if rule.pattern is None or rule.id in skip_rules or (rule.exts and ext not in rule.exts):
            continue
        for i, line in enumerate(lines, 1):
            if len(line) > 2000 or not rule.pattern.search(line) or _suppressed(line, rule.id):
                continue
            if rule.id == "MCP001" and COMMENT_RE.match(line):
                continue  # prose or commented-out code
            snippet = _redact(line, rule.pattern) if rule.redact else line
            findings.append(Finding(rule.id, rule.title, rule.severity, rel, i,
                                    snippet.strip()[:200], rule.message, rule.remediation))

    # Hidden unicode (a BOM at file start is normal, so skip position 0).
    for i, line in enumerate(lines, 1):
        probe = line[1:] if i == 1 and line.startswith(BOM) else line
        prose = ext in PROSE_EXTS
        hit = (HIDDEN_STRICT.search(probe) or ZW_RUN.search(probe)) if prose else HIDDEN_CHARS.search(probe)
        if hit and not _suppressed(line, "MCP008"):
            r = RULES["MCP008"]
            shown = HIDDEN_CHARS.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", probe)
            findings.append(Finding(r.id, r.title, r.severity, rel, i, shown.strip()[:200],
                                    r.message, r.remediation))

    auth = ctx.has_auth if ctx else None
    guard = ctx.has_guard if ctx else None
    file_level = checks.check_network_auth(rel, text, ext, auth)
    if ast_findings is None:  # Python handled by pyast; JS/TS and unparsable files use regex
        file_level += checks.check_file_read(rel, text, ext, guard)
    file_level += checks.check_dependencies(rel, text, name) + checks.check_broad_scope(rel, text, ext)
    for f in file_level:
        findings.append(f)

    # Inline suppressions apply to every finding, including AST and file-level ones.
    return [f for f in findings
            if not (0 < f.line <= len(lines) and _suppressed(lines[f.line - 1], f.rule_id))]


def scan(path: str, include_tests: bool = False) -> ScanResult:
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(path)
    base = root.parent if root.is_file() else root
    loaded = []
    for p in _iter_files(root, include_tests):
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        loaded.append((p, text))

    ctx = build_context([(p.name, t) for p, t in loaded])
    findings: List[Finding] = []
    for p, text in loaded:
        findings.extend(scan_text(p.relative_to(base).as_posix(), text, p.name, ctx))
    count = len(loaded)

    unique = {(f.rule_id, f.file, f.line): f for f in findings}
    ordered = sorted(unique.values(),
                     key=lambda f: (-severity_rank(f.severity), f.file, f.line))
    return ScanResult(str(root), count, ordered)
