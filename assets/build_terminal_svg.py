"""Render a real mcp-vet scan as assets/terminal.svg.

Run from the repository root:  python assets/build_terminal_svg.py
The picture is generated from the tool's actual output, so it cannot drift from reality.
Every text segment is placed at an explicit column, so it renders the same everywhere
(SVG whitespace handling differs between viewers).
"""
import html
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = "examples/vulnerable-server"
OUT = os.path.join(ROOT, "assets", "terminal.svg")

COLORS = {
    "CRITICAL": "#FF6B6B", "HIGH": "#FF8E72", "MEDIUM": "#E3B341", "LOW": "#58A6FF",
    "INFO": "#8B949E",
}
FG, DIM, FILE, GREEN = "#C9D1D9", "#8B949E", "#79C0FF", "#3FB950"
CHAR_W, LINE_H, MAX_COLS, LEFT = 8.43, 21, 98, 28
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"


def run_scan() -> list:
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"), PYTHONIOENCODING="utf-8")
    proc = subprocess.run([sys.executable, "-m", "mcp_vet", TARGET, "--min-severity", "LOW"],
                          cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8")
    lines = proc.stdout.splitlines()
    # Never print the machine's absolute path in a public image.
    if lines and lines[0].startswith("mcp-vet"):
        lines[0] = f"{lines[0].split(' in ')[0]} in {TARGET}"
    return [ln for ln in lines if not ln.startswith("Run with --format")]


def clip(text: str) -> str:
    return text if len(text) <= MAX_COLS else text[: MAX_COLS - 1] + "…"


def segments(line: str) -> list:
    """Split one output line into (text, color, bold) pieces."""
    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    for sev, color in COLORS.items():
        if stripped.startswith(sev + " "):
            rest = stripped[len(sev):].strip()
            rule, _, tail = rest.partition(" ")
            return [(" " * indent, FG, False), (sev, color, True),
                    (" " * (9 - len(sev)), FG, False), (rule, FG, True), (" " + tail.strip(), FG, False)]
    if stripped.startswith(">"):
        return [(line, DIM, False)]
    if line.startswith("Summary:"):
        out = [("Summary: ", FG, True)]
        for part in line[len("Summary: "):].split(", "):
            n, _, sev = part.partition(" ")
            out += [(n + " ", FG, False), (sev, COLORS.get(sev, FG), True), ("  ", FG, False)]
        return out
    if line.startswith("mcp-vet"):
        return [(line, DIM, False)]
    if line and not line.startswith(" "):
        return [(line, FILE, False)]
    return [(line, FG, False)]


def text_el(x: float, y: float, text: str, color: str, bold: bool = False) -> str:
    if not text.strip():
        return ""
    weight = ' font-weight="700"' if bold else ""
    return f'<text x="{x:.1f}" y="{y}" fill="{color}"{weight}>{html.escape(text.strip())}</text>'


def main() -> None:
    body = [clip(ln) for ln in run_scan()]
    rows = [[("$ ", GREEN, True), (f"mcp-vet {TARGET}", FG, False)]] + [segments(ln) for ln in body]
    width = int(MAX_COLS * CHAR_W + 2 * LEFT)
    top = 52
    height = top + len(rows) * LINE_H + 28
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
        f'height="{height}" role="img" aria-label="Terminal showing mcp-vet scanning a deliberately vulnerable MCP server">',
        f'<rect width="{width}" height="{height}" rx="12" fill="#0D1117"/>',
        f'<rect width="{width}" height="36" rx="12" fill="#161B22"/>',
        f'<rect y="24" width="{width}" height="12" fill="#161B22"/>',
        '<circle cx="22" cy="18" r="6" fill="#FF5F56"/><circle cx="42" cy="18" r="6" fill="#FFBD2E"/>'
        '<circle cx="62" cy="18" r="6" fill="#27C93F"/>',
        f'<text x="{width // 2}" y="23" text-anchor="middle" font-size="13" fill="#8B949E" '
        f'font-family="ui-sans-serif, system-ui, \'Segoe UI\', sans-serif">mcp-vet</text>',
        f'<g font-family="{FONT}" font-size="14">',
    ]
    for i, segs in enumerate(rows):
        y, col = top + i * LINE_H, 0
        for text, color, bold in segs:
            lead = len(text) - len(text.lstrip())
            out.append(text_el(LEFT + (col + lead) * CHAR_W, y, text, color, bold))
            col += len(text)
    out += ["</g>", "</svg>", ""]
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(s for s in out if s))
    print(f"wrote {OUT} ({width}x{height}, {len(rows)} lines)")


def find_browser():
    """A Chromium-based browser for rasterizing, or None."""
    import shutil
    candidates = [os.environ.get("BROWSER", "")]
    for name in ("msedge", "chrome", "google-chrome", "chromium", "chromium-browser"):
        candidates.append(shutil.which(name) or "")
    candidates += [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    return next((c for c in candidates if c and os.path.exists(c)), None)


def rasterize() -> None:
    """Render banner.svg and terminal.svg to 2x PNGs (PyPI cannot show SVG images)."""
    browser = find_browser()
    if not browser:
        sys.exit("no Chromium-based browser found; set BROWSER to its path")
    sizes = {"banner": (1200, 300), "terminal": None}
    with open(OUT, encoding="utf-8") as fh:
        head = fh.read(400)
    import re
    m = re.search(r'viewBox="0 0 (\d+) (\d+)"', head)
    sizes["terminal"] = (int(m.group(1)), int(m.group(2)))
    for name, (w, h) in sizes.items():
        svg = os.path.join(ROOT, "assets", f"{name}.svg")
        png = os.path.join(ROOT, "assets", f"{name}.png")
        subprocess.run([browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                        "--force-device-scale-factor=2", f"--screenshot={png}",
                        f"--window-size={w},{h}", "file:///" + svg.replace(os.sep, "/")],
                       check=True, capture_output=True)
        print(f"wrote {png}")


if __name__ == "__main__":
    main()
    if "--png" in sys.argv:
        rasterize()
