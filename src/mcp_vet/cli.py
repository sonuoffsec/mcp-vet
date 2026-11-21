from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__, baseline as baseline_mod, clients, config as config_mod
from .models import SEVERITIES, ScanResult, severity_rank
from .report import DEFAULT_LIMIT, as_json, as_sarif, as_text, rules_table
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-vet",
                                description="Static security scanner for MCP servers.")
    p.add_argument("path", nargs="?", help="directory or file to scan")
    p.add_argument("--clients", action="store_true",
                   help="scan the MCP client configs found on this machine (Claude Desktop, Cursor, "
                        "VS Code, Windsurf, Claude Code); files are only read, nothing is sent anywhere")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--fail-on", choices=SEVERITIES, default=None,
                   help="exit with code 1 if a finding at or above this severity exists (default HIGH)")
    p.add_argument("--min-severity", choices=SEVERITIES, default=None,
                   help="hide findings below this severity (default INFO)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show the offending code for each finding and how to fix each rule")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT, metavar="N",
                   help=f"list at most N findings in the text report (default {DEFAULT_LIMIT}); "
                        "critical and high findings are always listed")
    p.add_argument("--all", action="store_true", help="list every finding in the text report")
    p.add_argument("--no-color", action="store_true", help="never use colour (also honours NO_COLOR)")
    p.add_argument("--config", metavar="FILE",
                   help="use this config file instead of looking for .mcp-vet.toml")
    p.add_argument("--no-config", action="store_true", help="ignore any .mcp-vet.toml")
    p.add_argument("--baseline", metavar="FILE",
                   help="hide findings already accepted in this baseline file; only new ones are reported")
    p.add_argument("--write-baseline", metavar="FILE",
                   help="accept every current finding by writing it to FILE, then exit")
    p.add_argument("--include-tests", action="store_true",
                   help="also scan test files and test directories (skipped by default)")
    p.add_argument("--list-rules", action="store_true", help="print all rules and exit")
    p.add_argument("--version", action="version", version=f"mcp-vet {__version__}")
    return p


def _scan_clients(found, include_tests: bool) -> ScanResult:
    """Scan every client config in `found` and merge the results."""
    findings, files, elapsed, started = [], 0, 0.0, ""
    for path in found:
        r = scan(str(path), include_tests=include_tests)
        shown = clients.display(path)
        findings += [replace(f, file=shown) for f in r.findings]
        files, elapsed, started = files + r.files_scanned, elapsed + r.elapsed, started or r.started
    findings.sort(key=lambda f: (-severity_rank(f.severity), f.file, f.line))
    label = f"{len(found)} MCP client config file{'s' if len(found) != 1 else ''}"
    return ScanResult(label, files, findings, elapsed, started)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        print(rules_table())
        return 0
    if not args.path and not args.clients:
        print("error: give a path to scan, or use --clients", file=sys.stderr)
        return 2

    # Configuration: flags on the command line always win over the config file.
    cfg = None
    try:
        if args.config:
            cfg = config_mod.load(Path(args.config))
        elif not args.no_config and args.path:
            found_cfg = config_mod.find(args.path)
            cfg = config_mod.load(found_cfg) if found_cfg else None
    except config_mod.ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    include_tests = args.include_tests or bool(cfg and cfg.include_tests)

    try:
        if args.clients:
            found = clients.existing_configs()
            if not found:
                print("No MCP client configuration was found. Looked for Claude Desktop, VS Code, "
                      "Cursor, Windsurf and Claude Code configs.\n"
                      "Pass a file or folder instead: mcp-vet <path>")
                return 0
            result = _scan_clients(found, include_tests)
            target = result.root
        else:
            result = scan(args.path, include_tests=include_tests)
            target = args.path
    except FileNotFoundError:
        print(f"error: {args.path} not found", file=sys.stderr)
        return 2

    if cfg:
        config_mod.apply(result, cfg)
    min_sev = args.min_severity or (cfg.min_severity if cfg else None) or "INFO"
    fail_on = args.fail_on or (cfg.fail_on if cfg else None) or "HIGH"
    floor = severity_rank(min_sev)
    result.findings = [f for f in result.findings if severity_rank(f.severity) >= floor]

    try:
        if args.write_baseline:
            baseline_mod.write(args.write_baseline, result.findings)
            n = len(result.findings)
            print(f"Wrote {n} finding{'s' if n != 1 else ''} to {args.write_baseline}. "
                  f"Run with --baseline {args.write_baseline} to report only findings that are new.")
            return 0
        if args.baseline:
            result.findings, result.baselined = baseline_mod.filter_new(
                result.findings, baseline_mod.load(args.baseline))
    except baseline_mod.BaselineError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        text = as_json(result)
    elif args.format == "sarif":
        text = as_sarif(result)
    else:
        color = (sys.stdout.isatty() and not args.output and not args.no_color
                 and "NO_COLOR" not in os.environ)
        text = as_text(result, color=color, verbose=args.verbose, target=target,
                       limit=None if args.all else args.limit)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        if hasattr(sys.stdout, "reconfigure"):  # absent on captured or replaced streams
            sys.stdout.reconfigure(encoding="utf-8")
        print(text)

    gate = severity_rank(fail_on)
    return 1 if any(severity_rank(f.severity) >= gate for f in result.findings) else 0
