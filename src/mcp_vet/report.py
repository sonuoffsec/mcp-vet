from __future__ import annotations

import json
import shutil
import textwrap
from typing import Optional

from . import __version__
from .models import ScanResult, SEVERITIES, severity_rank
from .rules import RULES

TAGLINE = "Vet your MCP servers before your AI trusts them."
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
CYAN, GREEN, YELLOW = "\033[36m", "\033[32m", "\033[33m"
SEV_COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[38;5;208m", "MEDIUM": "\033[33m",
             "LOW": "\033[34m", "INFO": "\033[2m"}
SEV_LABEL = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
ALWAYS_SHOWN = ("CRITICAL", "HIGH")  # never hidden by --limit
DEFAULT_LIMIT = 10


class _Paint:
    """Wrap text in ANSI codes, or return it untouched when colour is off."""

    def __init__(self, on: bool):
        self.on = on

    def __call__(self, text: str, *codes: str) -> str:
        return f"{''.join(codes)}{text}{RESET}" if self.on and codes else text


def _secs(seconds: float) -> str:
    return "<0.01s" if seconds < 0.01 else f"{seconds:.2f}s"


def _select(result: ScanResult, limit: Optional[int]):
    """Findings to list. Critical and high are always listed; limit caps only the rest."""
    if limit is None:
        return list(result.findings)
    shown = [f for f in result.findings if f.severity in ALWAYS_SHOWN]
    for f in result.findings:
        if len(shown) >= limit:
            break
        if f.severity not in ALWAYS_SHOWN:
            shown.append(f)
    return sorted(shown, key=lambda f: (-severity_rank(f.severity), f.file, f.line))


def as_text(result: ScanResult, color: bool = False, verbose: bool = False,
            limit: Optional[int] = DEFAULT_LIMIT, target: Optional[str] = None,
            width: Optional[int] = None) -> str:
    p = _Paint(color)
    width = max(72, min(width or shutil.get_terminal_size((100, 24)).columns, 100))
    counts, total = result.counts(), len(result.findings)
    out = [f"{p('mcp-vet', BOLD, CYAN)} {p(__version__, DIM)}   {p(TAGLINE, DIM)}",
           p("─" * width, DIM), ""]

    info = [("▶", "Scanning target", target or result.root),
            (" ", "Scan mode", "static analysis (your code is never run)"),
            (" ", "Rules loaded", f"{len(RULES)} checks"),
            (" ", "Files scanned", str(result.files_scanned)),
            (" ", "Started at", result.started or "-")]
    if result.config_source:
        info.append((" ", "Config", result.config_source))
    if result.baselined:
        info.append((" ", "Baseline", f"{result.baselined} accepted finding"
                     f"{'s' if result.baselined != 1 else ''} hidden"))
    for sym, label, value in info:
        out.append(f"  {p(sym, CYAN)} {label:<15} : {value}")
    out += ["",
            f"  {p('✔', GREEN)} {p('Scan completed in ' + _secs(result.elapsed), BOLD, GREEN)}"
            f"      Total findings: {p(str(total), BOLD, YELLOW if total else GREEN)}",
            p("─" * width, DIM), ""]

    out.append(p("Findings summary", BOLD, CYAN))
    parts = [f"{p('●', SEV_COLOR[s])} {SEV_LABEL[s]} {p(str(counts[s]), BOLD)}"
             for s in reversed(SEVERITIES) if s != "INFO" or counts[s]]
    out += ["  " + "    ".join(parts), ""]

    shown = _select(result, limit)
    if shown:
        out.append(p("Details", BOLD, CYAN))
        locs = []
        for f in shown:
            loc = f"{f.file}:{f.line}"
            locs.append(loc if len(loc) <= 40 else "…" + loc[-39:])
        locw = max(len(x) for x in locs)
        titlew = max(20, width - (2 + 8 + 2 + 6 + 2) - locw - 2)
        for f, loc in zip(shown, locs):
            title = f.title if len(f.title) <= titlew else f.title[:titlew - 1] + "…"
            out.append(f"  {p(f'{f.severity:<8}', SEV_COLOR[f.severity])}  {p(f'{f.rule_id:<6}', BOLD)}"
                       f"  {title:<{titlew}}  {p(f'{loc:>{locw}}', DIM)}")
            if verbose:
                out.append(p(f"            > {f.snippet}", DIM))
        more = total - len(shown)
        if more:
            out.append(p(f"  … and {more} more finding{'s' if more != 1 else ''}"
                         " (use --all to list every finding)", DIM))
        if verbose:
            out += ["", p("How to fix", BOLD, CYAN)]
            seen = set()
            for f in shown:
                if f.rule_id in seen:
                    continue
                seen.add(f.rule_id)
                prefix = f"  {f.rule_id}  "
                out.append(textwrap.fill(f.remediation, width=width, initial_indent=prefix,
                                         subsequent_indent=" " * len(prefix)))
        out.append("")

    out.append(p("Recommendation", BOLD, CYAN))
    if counts["CRITICAL"] or counts["HIGH"]:
        out.append("  Fix the critical and high findings first, then review the rest.")
    elif total:
        out.append("  Review the findings above. Medium and low findings are weaker signals and can be"
                   " false positives.")
    else:
        out.append("  No findings. A clean report is not a guarantee: static analysis cannot see everything.")
    if total and not verbose:
        out.append(p("  Run with -v for the offending code and a suggested fix for each rule.", DIM))
    out += ["", p("─" * width, DIM), f"{p('✔', GREEN)} {p('Scan finished', GREEN)}"]
    return "\n".join(out)


def as_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "mcp-vet",
        "version": __version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "baselined": result.baselined,
        "summary": result.counts(),
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2)


def as_sarif(result: ScanResult) -> str:
    level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
             "LOW": "note", "INFO": "note"}
    rules = [{
        "id": r.id,
        "name": r.title,
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": r.message},
        "help": {"text": r.remediation},
        "defaultConfiguration": {"level": level[r.severity]},
    } for r in RULES.values()]
    results = [{
        "ruleId": f.rule_id,
        "level": level[f.severity],
        "message": {"text": f"{f.title}: {f.message}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.file},
            "region": {"startLine": f.line},
        }}],
    } for f in result.findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "mcp-vet", "version": __version__,
                                      "rules": rules}}, "results": results}],
    }, indent=2)


def rules_table() -> str:
    lines = [f"{'ID':<8}{'SEVERITY':<10}TITLE"]
    for r in RULES.values():
        lines.append(f"{r.id:<8}{r.severity:<10}{r.title}")
    return "\n".join(lines)
