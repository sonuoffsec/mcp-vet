from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import List, Optional

from dataclasses import replace

from . import checks, jsflow, pyast, unicode_check
from .models import Finding, ScanResult, SEVERITIES, severity_rank
from .rules import RULES, PROSE_EXTS, CODE_EXTS

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             ".tox", ".mypy_cache", ".pytest_cache", "site-packages"}
SCAN_EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts", ".json", ".yaml", ".yml",
             ".toml", ".md", ".txt", ".env"}
MAX_BYTES = 1_000_000
MAX_UNICODE_PER_FILE = 3
JS_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"}
AWS_DOC_KEY = "AKIAIOSFODNN7" + "EXAMPLE"  # the key AWS publishes in its documentation
DECLARATION = re.compile(r"(\bexec(Sync)?\s*\(\s*\w+\??\s*:\s*[A-Za-z\[{]|\bexec(Sync)?\s*\(\s*\)\s*[:{])")
EXEC_ONLY = re.compile(r"(?<![\w.$])exec(Sync)?\s*\(")
DYNAMIC_CODE = re.compile(r"(?<![\w.$])eval\(|new\s+Function\s*\(")
SECRET_CONTEXT = re.compile(r"(example|placeholder|dummy|fake|redact|regex|pattern|allow)", re.IGNORECASE)
NON_RUNTIME_DIRS = {"scripts", "script", ".github", "docs", "doc", "benchmarks", "benchmark", "ci", "demo", "demos"}
DEMOTE_RULES = {"MCP001", "MCP002", "MCP004", "MCP005", "MCP009", "MCP012"}
COMMENT_RE = re.compile(r"\s*(//|/\*|\*|#)")
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "e2e", "fixtures", "fixture",
             "__fixtures__", "testdata", "__mocks__", "mocks"}
# Type declarations and minified bundles never hold the server's own logic.
GENERATED_RE = re.compile(r"(\.d\.(ts|mts|cts)$|\.min\.(js|mjs|cjs)$)", re.IGNORECASE)
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
            if GENERATED_RE.search(name):
                continue
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


MANIFESTS = {"requirements.txt", "pyproject.toml", "setup.py", "package.json", "Dockerfile", "go.mod"}


class ProjectContext:
    """Facts gathered per app. An app is a folder with its own manifest (requirements.txt,
    package.json, Dockerfile...). Auth or path-guard code anywhere in the app, or in a
    parent folder, counts. This keeps one app's auth from hiding another app's gap."""

    def __init__(self, manifest_dirs=None, auth_dirs=None, guard_dirs=None):
        self.manifest_dirs = manifest_dirs or set()
        self.auth_dirs = auth_dirs or set()
        self.guard_dirs = guard_dirs or set()

    def chain(self, rel: str) -> List[str]:
        parts = rel.split("/")[:-1]
        out = []
        while parts:
            d = "/".join(parts)
            if d in self.manifest_dirs:
                out.append(d)
            parts.pop()
        out.append("")
        return out

    def owner(self, rel: str) -> str:
        return self.chain(rel)[0]

    def has_auth_for(self, rel: str) -> bool:
        return any(d in self.auth_dirs for d in self.chain(rel))

    def has_guard_for(self, rel: str) -> bool:
        return any(d in self.guard_dirs for d in self.chain(rel))


def build_context(files: List[tuple]) -> ProjectContext:
    """files: (relative posix path, text) pairs."""
    manifest_dirs = set()
    for rel, _ in files:
        if Path(rel).name in MANIFESTS:
            d = Path(rel).parent.as_posix()
            manifest_dirs.add("" if d == "." else d)
    ctx = ProjectContext(manifest_dirs)
    for rel, text in files:
        if Path(rel).suffix.lower() not in CODE_EXTS:
            continue
        owner = ctx.owner(rel)
        if checks.AUTH_HINT.search(text):
            ctx.auth_dirs.add(owner)
        if checks.PATH_GUARD.search(text):
            ctx.guard_dirs.add(owner)
    return ctx


def scan_text(rel: str, text: str, name: str, ctx: Optional[ProjectContext] = None) -> List[Finding]:
    ext = Path(name).suffix.lower()
    lines = text.splitlines()
    findings: List[Finding] = []

    # Python gets AST analysis and JS/TS gets the token-level analyzer (both taint-aware).
    # If analysis fails we fall back to line patterns.
    if ext == ".py":
        ast_findings = pyast.analyze(rel, text)
    elif ext in JS_EXTS:
        ast_findings = jsflow.analyze(rel, text)
    else:
        ast_findings = None
    skip_rules = {"MCP001"} if ast_findings is not None else set()
    if ast_findings:
        findings.extend(ast_findings)

    uses_child_process = "child_process" in text
    for rule in RULES.values():
        if rule.pattern is None or rule.id in skip_rules or (rule.exts and ext not in rule.exts):
            continue
        for i, line in enumerate(lines, 1):
            if len(line) > 2000 or not rule.pattern.search(line) or _suppressed(line, rule.id):
                continue
            severity = rule.severity
            if rule.id == "MCP001":
                if COMMENT_RE.match(line):
                    continue  # prose or commented-out code
                # A bare exec( is only a shell call if the file imports child_process.
                if not uses_child_process and EXEC_ONLY.search(line) and not DYNAMIC_CODE.search(line):
                    continue
                if DECLARATION.search(line):
                    continue  # a method signature, not a call
                severity = "MEDIUM"  # regex mode has no taint information
            if rule.id == "MCP002":
                hit = rule.pattern.search(line)
                if hit and hit.group(0).lower().startswith(("do not", "before")):
                    severity = "MEDIUM"  # this wording also appears in legitimate prompts
            if rule.id == "MCP003":
                if not _real_secret_hits(line, ext, rule.pattern):
                    continue
            snippet = _redact(line, rule.pattern) if rule.redact else line
            findings.append(Finding(rule.id, rule.title, severity, rel, i,
                                    snippet.strip()[:200], rule.message, rule.remediation))

    # Hidden unicode: tolerant of emoji, RTL scripts and defensive code. Capped per file.
    r8 = RULES["MCP008"]
    hidden = []
    for i, line in enumerate(lines, 1):
        shown = unicode_check.suspicious(line, ext in PROSE_EXTS, first_line=(i == 1))
        if shown is not None and not _suppressed(line, "MCP008"):
            hidden.append(Finding(r8.id, r8.title, r8.severity, rel, i, shown, r8.message, r8.remediation))
    if len(hidden) > MAX_UNICODE_PER_FILE:
        extra = len(hidden) - MAX_UNICODE_PER_FILE
        hidden = hidden[:MAX_UNICODE_PER_FILE]
        hidden[-1] = replace(hidden[-1], snippet=hidden[-1].snippet[:150] + f"  (+{extra} more in this file)")
    findings.extend(hidden)

    auth = ctx.has_auth_for(rel) if ctx else None
    guard = ctx.has_guard_for(rel) if ctx else None
    file_level = checks.check_network_auth(rel, text, ext, auth)
    if ast_findings is None:  # Python handled by pyast; JS/TS and unparsable files use regex
        file_level += checks.check_file_read(rel, text, ext, guard)
    file_level += checks.check_dependencies(rel, text, name) + checks.check_broad_scope(rel, text, ext)
    file_level += checks.check_credentials(rel, text, ext, name) + checks.check_obfuscation(rel, text, ext)
    file_level += checks.check_launch_config(rel, text, ext)
    for f in file_level:
        findings.append(f)

    # Inline suppressions apply to every finding, including AST and file-level ones.
    kept = [f for f in findings
            if not (0 < f.line <= len(lines) and _suppressed(lines[f.line - 1], f.rule_id))]
    return [_demote_if_not_runtime(f) for f in kept]


def _real_secret_hits(line: str, ext: str, pattern: re.Pattern) -> bool:
    """False for placeholders: docs, redaction filters, allowlists, well-known example keys."""
    for m in pattern.finditer(line):
        value = m.group(0)
        if ext in PROSE_EXTS and (value == AWS_DOC_KEY or "PRIVATE KEY" in value):
            continue
        if SECRET_CONTEXT.search(line.replace(value, "")):
            continue
        return True
    return False


def _demote_if_not_runtime(f: Finding) -> Finding:
    """Findings in build scripts, CI and docs matter less than in the shipped server."""
    if f.rule_id not in DEMOTE_RULES:
        return f
    parts = {p.lower() for p in Path(f.file).parts[:-1]}
    if not parts & NON_RUNTIME_DIRS:
        return f
    return replace(f, severity=SEVERITIES[max(severity_rank(f.severity) - 1, 0)])


def scan(path: str, include_tests: bool = False) -> ScanResult:
    t0, started = time.perf_counter(), time.strftime("%H:%M:%S")
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

    ctx = build_context([(p.relative_to(base).as_posix(), t) for p, t in loaded])
    findings: List[Finding] = []
    for p, text in loaded:
        findings.extend(scan_text(p.relative_to(base).as_posix(), text, p.name, ctx))
    count = len(loaded)

    unique = {(f.rule_id, f.file, f.line): f for f in findings}
    ordered = sorted(unique.values(),
                     key=lambda f: (-severity_rank(f.severity), f.file, f.line))
    return ScanResult(str(root), count, ordered, time.perf_counter() - t0, started)
