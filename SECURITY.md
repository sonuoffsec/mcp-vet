# Security Policy

## Reporting a vulnerability in mcp-vet

If you find a security issue in mcp-vet itself (for example, a crafted file that makes the scanner crash, hang, or read files outside the scanned path), please report it privately instead of opening a public issue.

Use GitHub's private reporting: **Security tab > Report a vulnerability** on this repository.

Please include the mcp-vet version (`mcp-vet --version`), the steps to reproduce, and the impact you see. You can expect an initial reply within 7 days.

## Scope

mcp-vet is a static analyzer. It parses text and Python syntax trees and does not execute scanned code. Reports about the scanner's own behavior are in scope. Findings the scanner reports about *other* projects are not vulnerabilities in mcp-vet.

## Supported versions

Only the latest release receives fixes.
