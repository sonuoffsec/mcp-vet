## What changed

## How I checked it

- [ ] Tests pass: `python -m unittest discover -s tests`
- [ ] `python -m mcp_vet src` still finds nothing
- [ ] New or changed rules have a vulnerable snippet **and** a safe twin in the recall suite
- [ ] I looked at real code for false positives (how many repositories, how many findings, how many real)
- [ ] `CHANGELOG.md` and the README are updated if behaviour changed
