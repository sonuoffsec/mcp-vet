"""Hidden-Unicode detection that tolerates legitimate uses.

Zero-width and directional characters are normal in emoji sequences, Persian/Hebrew/
Arabic/Indic text, and in code that sanitizes them. They are suspicious when they
appear on their own inside code, config, or tool descriptions.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Optional

from .rules import HIDDEN_CHARS, HIDDEN_STRICT, ZW_RUN

BOM = chr(0xFEFF)
# Hebrew, Arabic, Syriac, Thaana, N'Ko and presentation forms.
RTL = re.compile(
    "[" + chr(0x0590) + "-" + chr(0x08FF) + chr(0xFB1D) + "-" + chr(0xFDFF)
    + chr(0xFE70) + "-" + chr(0xFEFE) + "]"
)
# Lines that clean, match or strip these characters are defensive code, not a payload.
DEFENSIVE = re.compile(
    r"(re\.(compile|sub|match|search|findall)\(|RegExp\(|\.replace(All)?\(|\.strip\(|"
    r"\.lstrip\(|\.rstrip\(|\.test\(|\.normalize\(|/[gimsuyd]{0,5}\s*[;,)\]]|\\s)"
)


def _is_emoji(ch: str) -> bool:
    if not ch:
        return False
    cp = ord(ch)
    return cp >= 0x1F000 or 0x2190 <= cp <= 0x2BFF or cp == 0xFE0F


def _letter_or_mark(ch: str) -> bool:
    return bool(ch) and unicodedata.category(ch)[0] in "LM"


def _shown(probe: str) -> str:
    return HIDDEN_CHARS.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", probe).strip()[:200]


def suspicious(line: str, prose: bool, first_line: bool = False) -> Optional[str]:
    """Return a printable snippet if the line hides text, otherwise None."""
    probe = line[1:] if first_line and line.startswith(BOM) else line
    if prose:  # README/text: only the unambiguous cases
        if HIDDEN_STRICT.search(probe) or ZW_RUN.search(probe):
            return _shown(probe)
        return None

    matches = list(HIDDEN_CHARS.finditer(probe))
    if not matches or DEFENSIVE.search(probe):
        return None
    if ZW_RUN.search(probe):
        return _shown(probe)

    has_rtl = RTL.search(probe) is not None
    for m in matches:
        c = ord(m.group(0))
        prev = probe[m.start() - 1] if m.start() > 0 else ""
        nxt = probe[m.end()] if m.end() < len(probe) else ""
        if c == 0x200B and prev == "*" and nxt == "/":
            continue  # escapes a comment terminator inside a comment
        if c in (0x200C, 0x200D):  # ZWNJ / ZWJ
            if _is_emoji(prev) or _is_emoji(nxt):
                continue
            if prev and nxt and ord(prev) > 0x7F and ord(nxt) > 0x7F \
                    and _letter_or_mark(prev) and _letter_or_mark(nxt):
                continue
        elif c in (0x200E, 0x200F):  # LRM / RLM
            if has_rtl:
                continue
        return _shown(probe)
    return None
