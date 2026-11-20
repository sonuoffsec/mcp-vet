# Releasing mcp-vet

Releases are published to PyPI by `.github/workflows/release.yml` when a GitHub release is
published. It uses PyPI **trusted publishing** (OpenID Connect), so there is no API token to
create, store or leak.

## One-time setup (about five minutes)

1. Create an account on https://pypi.org and enable two-factor authentication.
2. On PyPI go to **Your account > Publishing > Add a new pending publisher** and enter:
   - PyPI project name: `mcp-vet`
   - Owner: `sonuoffsec`
   - Repository name: `mcp-vet`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. On GitHub go to the repository **Settings > Environments > New environment**, name it
   `pypi`, and (recommended) add yourself as a required reviewer so every upload needs a click.

The first successful release creates the `mcp-vet` project on PyPI and turns the pending
publisher into a normal one.

## Each release

1. Update `__version__` in `src/mcp_vet/__init__.py` and `version` in `pyproject.toml`
   (they must match), and add an entry to `CHANGELOG.md`.
2. Regenerate the README images if output changed: `python assets/build_terminal_svg.py --png`.
3. Run the tests: `python -m unittest discover -s tests` and `python tests/test_recall.py`.
4. Commit, push, and wait for CI to pass on `main`.
5. Create the release: `gh release create vX.Y.Z --title "vX.Y.Z" --notes-file <notes>`
   (or use the GitHub web UI). Publishing the release starts the workflow.
6. Approve the `pypi` environment deployment if you set a required reviewer.

## Checking a build locally without publishing

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
```
