"""Recall and false-positive suite. Run `python tests/test_recall.py` for a table."""
import os
import sys
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp_vet.models import severity_rank  # noqa: E402
from mcp_vet.scanner import scan_text  # noqa: E402
from recall_cases import SAFE, VULNERABLE  # noqa: E402


def _code(c):
    return c() if callable(c) else c


def run_vulnerable():
    """Yield (case id, expected rules, found rules)."""
    for cid, fname, code, expected in VULNERABLE:
        found = {f.rule_id for f in scan_text(fname, _code(code), fname)}
        yield cid, expected, found


def run_safe():
    """Yield (case id, findings at MEDIUM or above)."""
    for cid, fname, code in SAFE:
        loud = [f for f in scan_text(fname, _code(code), fname)
                if severity_rank(f.severity) >= severity_rank("MEDIUM")]
        yield cid, loud


class Recall(unittest.TestCase):
    def test_every_vulnerable_case_is_detected(self):
        misses = [f"{cid}: expected {sorted(exp)}, found {sorted(found)}"
                  for cid, exp, found in run_vulnerable() if not set(exp) <= found]
        self.assertEqual(misses, [], "missed known-vulnerable cases:\n  " + "\n  ".join(misses))

    def test_no_safe_case_is_flagged(self):
        noisy = [f"{cid}: {[(f.rule_id, f.severity, f.line) for f in loud]}"
                 for cid, loud in run_safe() if loud]
        self.assertEqual(noisy, [], "false positives on safe cases:\n  " + "\n  ".join(noisy))


def report() -> None:
    per_rule = defaultdict(lambda: [0, 0])  # rule -> [detected, total]
    for cid, exp, found in run_vulnerable():
        for rule in exp:
            per_rule[rule][1] += 1
            per_rule[rule][0] += rule in found
    print("Recall by rule (author-written cases)")
    for rule in sorted(per_rule):
        d, t = per_rule[rule]
        print(f"  {rule}  {d}/{t}")
    det = sum(v[0] for v in per_rule.values())
    tot = sum(v[1] for v in per_rule.values())
    safe = list(run_safe())
    clean = sum(1 for _, loud in safe if not loud)
    print(f"Overall detection: {det}/{tot}")
    print(f"Safe cases with no MEDIUM+ finding: {clean}/{len(safe)}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--unittest":
        unittest.main(argv=[sys.argv[0]])
    else:
        report()
        sys.exit(0)
