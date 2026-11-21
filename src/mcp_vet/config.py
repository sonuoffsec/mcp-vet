"""Optional project configuration: a `.mcp-vet.toml` next to the code you scan.

    fail_on = "MEDIUM"            # exit 1 at or above this severity (the --fail-on flag wins)
    min_severity = "LOW"          # hide findings below this
    ignore = ["legacy/**", "vendor"]   # paths, relative to the scanned folder
    disable = ["MCP006"]          # rule ids to turn off
    include_tests = false

    [severity]
    MCP009 = "LOW"                # change a rule's severity, or "OFF" to disable it

Parsed with `tomllib` when Python has it (3.11+), otherwise with a small built-in reader that
understands exactly the subset above, so there is still no dependency.
"""
from __future__ import annotations

import difflib
import fnmatch
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional

from .models import SEVERITIES, ScanResult
from .rules import RULES

CONFIG_NAME = ".mcp-vet.toml"
TOP_LEVEL = {"fail_on", "min_severity", "ignore", "disable", "include_tests", "severity"}


class ConfigError(Exception):
    """The config file is unreadable or invalid. The message says what to fix."""


@dataclass
class Config:
    fail_on: Optional[str] = None
    min_severity: Optional[str] = None
    ignore: List[str] = field(default_factory=list)
    disable: List[str] = field(default_factory=list)
    severity: Dict[str, str] = field(default_factory=dict)
    include_tests: bool = False
    source: str = ""


# ----------------------------------------------------------------------------- tiny TOML subset
def _strip_comment(line: str) -> str:
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return line[:i]
    return line


def _split_items(body: str) -> List[str]:
    items, cur, quote = [], "", None
    for ch in body:
        if quote:
            cur += ch
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            cur += ch
        elif ch == ",":
            items.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        items.append(cur.strip())
    return items


def _value(raw: str):
    raw = raw.strip()
    if raw[:1] in "\"'" and raw[-1:] == raw[:1] and len(raw) >= 2:
        return raw[1:-1]
    if raw in ("true", "false"):
        return raw == "true"
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    if raw.startswith("[") and raw.endswith("]"):
        return [_value(i) for i in _split_items(raw[1:-1])]
    raise ValueError(f"cannot read the value {raw!r}")


def _mini_toml(text: str) -> dict:
    data: dict = {}
    table = data
    pending_key, pending = None, ""
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).strip()
        if pending_key is not None:  # inside a multi-line array
            pending += " " + line
            if pending.count("[") <= pending.count("]"):
                table[pending_key] = _value(pending)
                pending_key = None
            continue
        if not line:
            continue
        header = re.fullmatch(r"\[([A-Za-z0-9_.\-]+)\]", line)
        if header:
            table = data.setdefault(header.group(1), {})
            continue
        if "=" not in line:
            raise ValueError(f"line {n}: expected `key = value`")
        key, _, value = line.partition("=")
        key, value = key.strip().strip("\"'"), value.strip()
        if value.startswith("[") and value.count("[") > value.count("]"):
            pending_key, pending = key, value
            continue
        try:
            table[key] = _value(value)
        except ValueError as e:
            raise ValueError(f"line {n}: {e}") from None
    if pending_key is not None:
        raise ValueError("an array is never closed")
    return data


def _load_toml(text: str) -> dict:
    try:
        import tomllib  # Python 3.11+
        return tomllib.loads(text)
    except ImportError:
        return _mini_toml(text)


# ----------------------------------------------------------------------------- parsing and use
def _check_severity(name: str, value, where: str, allow_off: bool = True) -> str:
    allowed = SEVERITIES + (["OFF"] if allow_off else [])
    if not isinstance(value, str) or value.upper() not in allowed:
        raise ConfigError(f"{where}: {value!r} is not valid (use one of {', '.join(allowed)})")
    return value.upper()


def parse(text: str, source: str = CONFIG_NAME) -> Config:
    try:
        data = _load_toml(text)
    except Exception as e:  # tomllib.TOMLDecodeError or our ValueError
        raise ConfigError(f"{source}: {e}") from None
    for key in data:
        if key not in TOP_LEVEL:
            hint = difflib.get_close_matches(key, TOP_LEVEL, n=1)
            raise ConfigError(f"{source}: unknown setting {key!r}" + (f" (did you mean {hint[0]!r}?)" if hint else ""))
    cfg = Config(source=source)
    for key in ("fail_on", "min_severity"):
        if key in data:
            setattr(cfg, key, _check_severity(key, data[key], f"{source}: {key}", allow_off=False))
    for key in ("ignore", "disable"):
        if key in data:
            if not isinstance(data[key], list) or not all(isinstance(i, str) for i in data[key]):
                raise ConfigError(f"{source}: {key} must be a list of strings")
            setattr(cfg, key, list(data[key]))
    for rule in cfg.disable:
        if rule not in RULES:
            raise ConfigError(f"{source}: disable lists unknown rule {rule!r}")
    if "include_tests" in data:
        if not isinstance(data["include_tests"], bool):
            raise ConfigError(f"{source}: include_tests must be true or false")
        cfg.include_tests = data["include_tests"]
    for rule, sev in (data.get("severity") or {}).items():
        if rule not in RULES:
            raise ConfigError(f"{source}: [severity] names unknown rule {rule!r}")
        cfg.severity[rule] = _check_severity(rule, sev, f"{source}: [severity] {rule}")
    return cfg


def find(start: str) -> Optional[Path]:
    """The nearest .mcp-vet.toml in the scanned folder or up to four folders above it."""
    p = Path(start).resolve()
    p = p if p.is_dir() else p.parent
    for folder in [p] + list(p.parents)[:4]:
        candidate = folder / CONFIG_NAME
        if candidate.is_file():
            return candidate
    return None


def load(path: Path) -> Config:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e}") from None
    return parse(text, str(path.name))


def _ignored(file: str, patterns: List[str]) -> bool:
    for pattern in patterns:
        p = pattern.strip().replace("\\", "/").strip("/").replace("**", "*")
        if p and (file == p or file.startswith(p + "/") or fnmatch.fnmatch(file, p)
                  or fnmatch.fnmatch(file, p + "/*")):
            return True
    return False


def apply(result: ScanResult, cfg: Config) -> ScanResult:
    """Drop ignored paths and disabled rules, and apply severity overrides."""
    kept = []
    for f in result.findings:
        if f.rule_id in cfg.disable or _ignored(f.file, cfg.ignore):
            continue
        override = cfg.severity.get(f.rule_id)
        if override == "OFF":
            continue
        kept.append(replace(f, severity=override) if override else f)
    result.findings = kept
    result.config_source = cfg.source
    return result
