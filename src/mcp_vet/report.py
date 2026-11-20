from __future__ import annotations

import json
from itertools import groupby

from . import __version__
from .models import ScanResult, SEVERITIES
from .rules import RULES

COLORS = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
          "LOW": "\033[36m", "INFO": "\033[2m"}
RESET = "\033[0m"


def as_text(result: ScanResult, color: bool = False) -> str:
    def paint(sev: str) -> str:
        return f"{COLORS[sev]}{sev:<8}{RESET}" if color else f"{sev:<8}"

    out = [f"mcp-vet {__version__} - scanned {result.files_scanned} files in {result.root}", ""]
    by_file = sorted(result.findings, key=lambda f: (f.file, f.line))
    for file, items in groupby(by_file, key=lambda f: f.file):
        out.append(file)
        for f in items:
            out.append(f"  {paint(f.severity)} {f.rule_id}  line {f.line}  {f.title}")
            out.append(f"           > {f.snippet}")
        out.append("")
    counts = result.counts()
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s]]
    out.append("Summary: " + (", ".join(parts) if parts else "no findings"))
    if result.findings:
        out.append("Run with --format json for fix guidance on each rule.")
    return "\n".join(out)


def as_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "mcp-vet",
        "version": __version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
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
