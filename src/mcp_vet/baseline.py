"""A baseline lets a team adopt mcp-vet on an existing codebase.

`--write-baseline FILE` records today's findings as accepted. `--baseline FILE` then hides them,
so only findings that are new since the baseline are reported and can fail a build.

A finding's identity is its rule, file and offending code, not its line number, so moving code
around does not make an accepted finding reappear. Fixing the code retires the entry.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import List, Tuple

from . import __version__
from .models import Finding


class BaselineError(Exception):
    pass


def fingerprint(f: Finding) -> str:
    key = f"{f.rule_id}|{f.file}|{' '.join(f.snippet.split())}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def write(path: str, findings: List[Finding]) -> None:
    entries = [{"fingerprint": fingerprint(f), "rule_id": f.rule_id, "file": f.file,
                "line": f.line, "snippet": f.snippet} for f in findings]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"tool": "mcp-vet", "version": __version__, "baseline": 1, "findings": entries},
                  fh, indent=2)
        fh.write("\n")


def load(path: str) -> Counter:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return Counter(e["fingerprint"] for e in data["findings"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise BaselineError(f"cannot use baseline {path}: {e}") from None


def filter_new(findings: List[Finding], accepted: Counter) -> Tuple[List[Finding], int]:
    """Findings not in the baseline, and how many were hidden. Duplicates are matched one for one."""
    remaining = Counter(accepted)
    kept, hidden = [], 0
    for f in findings:
        fp = fingerprint(f)
        if remaining[fp] > 0:
            remaining[fp] -= 1
            hidden += 1
        else:
            kept.append(f)
    return kept, hidden
