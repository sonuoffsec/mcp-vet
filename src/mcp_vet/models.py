from __future__ import annotations

from dataclasses import dataclass, asdict

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str
    message: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    files_scanned: int
    findings: list
    elapsed: float = 0.0   # seconds the scan took
    started: str = ""      # local clock time the scan started, HH:MM:SS
    baselined: int = 0     # findings hidden because a baseline already accepted them
    config_source: str = ""  # the .mcp-vet.toml that was applied, if any

    def counts(self) -> dict:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] += 1
        return out
