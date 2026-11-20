"""Rule registry. Line rules carry a regex; file-level rules live in checks.py."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

CODE_EXTS = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx")
CONFIG_EXTS = (".json", ".yaml", ".yml")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    message: str
    remediation: str
    pattern: Optional[re.Pattern] = None
    exts: tuple = ()
    redact: bool = False


def _rx(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


RULES = {
    "MCP001": Rule(
        "MCP001", "Shell or dynamic code execution", "HIGH",
        "Tool code can run shell commands or evaluate dynamic code. If any argument "
        "comes from the model or a user, this is command injection.",
        "Avoid shell=True / exec / eval. Pass an argument list, validate against an allowlist.",
        pattern=_rx(
            r"(subprocess\.\w+\([^)]*shell\s*=\s*True"  # mcp-vet: ignore
            r"|\bos\.(system|popen)\s*\("  # mcp-vet: ignore
            r"|(?<![\w.$])(eval|exec)\("  # mcp-vet: ignore
            r"|\bchild_process\b.*\bexec(Sync)?\s*\("  # mcp-vet: ignore
            r"|(?<![\w.$])exec(Sync)?\s*\(\s*(`[^`]*\$\{|[^)\n]*\+)"  # mcp-vet: ignore
            r"|new\s+Function\s*\()"  # mcp-vet: ignore
        ),
        exts=CODE_EXTS,
    ),
    "MCP002": Rule(
        "MCP002", "Possible tool poisoning / hidden instructions", "HIGH",
        "Text aimed at the AI model (not the user) was found in code or tool metadata. "
        "Hidden instructions in tool descriptions can hijack the agent.",
        "Keep tool descriptions factual and short. Remove instructions that address the model.",
        pattern=_rx(
            r"(ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|rules)"  # mcp-vet: ignore
            r"|<\s*important\s*>"  # mcp-vet: ignore
            r"|do\s+not\s+(tell|mention|inform|reveal|show)[^.\n]{0,40}(user|human)"  # mcp-vet: ignore
            r"|\b(read|cat|send|upload|include|attach)\b[^.\n]{0,60}(~/\.ssh/id_|id_rsa|id_ed25519|/etc/passwd|/etc/shadow|\.aws/credentials)"  # mcp-vet: ignore
            r"|before\s+(using|calling)\s+this\s+tool[^.\n]{0,60}(first|must))"  # mcp-vet: ignore
        ),
        exts=CODE_EXTS + CONFIG_EXTS,
    ),
    "MCP003": Rule(
        "MCP003", "Hardcoded secret", "CRITICAL",
        "A value that looks like a live credential is committed in source or config.",
        "Revoke the secret, load it from the environment or a secret manager.",
        pattern=re.compile(
            r"(AKIA[0-9A-Z]{16}"
            r"|gh[pousr]_[A-Za-z0-9]{36,}"
            r"|sk-ant-[A-Za-z0-9_-]{20,}"
            r"|sk-[A-Za-z0-9]{32,}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,}"
            r"|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)"
        ),
        exts=CODE_EXTS + CONFIG_EXTS + (".env", ".toml", ".txt", ".md"),
        redact=True,
    ),
    "MCP004": Rule(
        "MCP004", "Network transport without authentication", "HIGH",
        "The server listens over HTTP/SSE and no authentication code was detected. "
        "Anyone who can reach the port can call your tools.",
        "Bind to 127.0.0.1, require a bearer token or OAuth, and validate the Origin header.",
    ),
    "MCP005": Rule(
        "MCP005", "Unrestricted file read in tool", "MEDIUM",
        "A tool reads files but no path-containment check (resolve + is_relative_to / "
        "startsWith) was detected. Path traversal may expose arbitrary files.",
        "Resolve the path, then verify it stays inside an allowed root before reading.",
    ),
    "MCP006": Rule(
        "MCP006", "Unpinned dependency", "LOW",
        "Dependency is not pinned to a version. A compromised release would be pulled in silently.",
        "Pin exact versions and use a lockfile.",
    ),
    "MCP007": Rule(
        "MCP007", "Overly broad filesystem scope", "HIGH",
        "An MCP config grants a server access to the filesystem root or the whole home directory.",
        "Scope the server to a single project directory.",
    ),
    "MCP009": Rule(
        "MCP009", "Tool input controls an outbound request", "MEDIUM",
        "A tool fetches a URL built from its arguments. An attacker can point it at "
        "internal services or cloud metadata endpoints (SSRF).",
        "Allowlist hosts, block private and link-local addresses, and disable redirects.",
    ),
    "MCP010": Rule(
        "MCP010", "SQL built from tool input", "HIGH",
        "A query is executed that contains, or is entirely supplied by, a tool argument. "
        "This allows SQL injection or arbitrary database access.",
        "Use parameterized queries (placeholders plus a parameter tuple). If the tool must run "
        "caller-supplied SQL, use a read-only database role.",
    ),
    "MCP011": Rule(
        "MCP011", "Unsafe deserialization of tool input", "HIGH",
        "A tool argument is passed to a deserializer that can execute code (pickle, marshal, "
        "unsafe YAML).",
        "Use JSON, or yaml.safe_load, and validate the result against a schema.",
    ),
    "MCP008": Rule(
        "MCP008", "Hidden Unicode characters", "HIGH",
        "Zero-width, bidirectional-control or tag characters were found. They can hide "
        "instructions from human reviewers while the model still reads them.",
        "Remove the characters and review the surrounding text.",
    ),
}

# Characters that are invisible or reorder text. Built from code points so this
# source file itself contains no hidden characters.
_HIDDEN_RANGES = [
    (0x200B, 0x200F),    # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),    # bidi embedding/override
    (0x2060, 0x2064),    # word joiner, invisible operators
    (0x2066, 0x2069),    # bidi isolates
    (0xE0000, 0xE007F),  # Unicode tag characters
]
HIDDEN_CHARS = re.compile(
    "[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _HIDDEN_RANGES) + "]"
)

# In prose (README/text) ZWNJ, ZWJ, ZWSP and LRM/RLM are normal in Persian, Thai, Indic
# scripts and emoji. There we only flag bidi overrides, tag characters, word joiners and
# runs of 3+ zero-width characters (the signature of text-hiding encodings).
_STRICT_RANGES = [(0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069), (0xE0000, 0xE007F)]
HIDDEN_STRICT = re.compile(
    "[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _STRICT_RANGES) + "]"
)
ZW_RUN = re.compile("[" + chr(0x200B) + "-" + chr(0x200F) + "]{3,}")
PROSE_EXTS = (".md", ".txt")
