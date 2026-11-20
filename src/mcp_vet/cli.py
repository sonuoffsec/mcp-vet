from __future__ import annotations

import argparse
import sys

from . import __version__
from .models import SEVERITIES, severity_rank
from .report import as_json, as_sarif, as_text, rules_table
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-vet",
                                description="Static security scanner for MCP servers.")
    p.add_argument("path", nargs="?", help="directory or file to scan")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--fail-on", choices=SEVERITIES, default="HIGH",
                   help="exit with code 1 if a finding at or above this severity exists (default HIGH)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="INFO",
                   help="hide findings below this severity")
    p.add_argument("--include-tests", action="store_true",
                   help="also scan test files and test directories (skipped by default)")
    p.add_argument("--list-rules", action="store_true", help="print all rules and exit")
    p.add_argument("--version", action="version", version=f"mcp-vet {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        print(rules_table())
        return 0
    if not args.path:
        print("error: path is required", file=sys.stderr)
        return 2
    try:
        result = scan(args.path, include_tests=args.include_tests)
    except FileNotFoundError:
        print(f"error: {args.path} not found", file=sys.stderr)
        return 2

    floor = severity_rank(args.min_severity)
    result.findings = [f for f in result.findings if severity_rank(f.severity) >= floor]

    if args.format == "json":
        text = as_json(result)
    elif args.format == "sarif":
        text = as_sarif(result)
    else:
        text = as_text(result, color=sys.stdout.isatty() and not args.output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(text)

    gate = severity_rank(args.fail_on)
    return 1 if any(severity_rank(f.severity) >= gate for f in result.findings) else 0
