# Security Policy

## Supported Versions

Security fixes are applied to the latest released minor version.

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report privately via one of:

- GitHub Security Advisory (preferred): <https://github.com/aplaceforallmystuff/mcp-homescan/security/advisories/new>
- Email: jim.christian@gmail.com with subject `mcp-homescan security`

Include:

- A description of the issue and its impact
- Reproduction steps or a proof-of-concept
- The version / commit affected
- Your name / handle if you'd like to be credited in the fix advisory

## Response Targets

| Stage | Target |
|-------|--------|
| Acknowledgement | 3 business days |
| Triage + severity assessment | 7 business days |
| Fix released (for confirmed issues) | 30 days, sooner for high/critical |

## Scope

In scope:

- The `mcp-homescan` MCP server source code in this repository
- The published npm package
- Tool-boundary input validation and shell-injection surfaces
- ARP parsing, subnet handling, and any code that invokes system binaries

Out of scope:

- Vulnerabilities in dependencies (report upstream; we will pick up patched releases)
- Issues requiring physical access to the host running the server
- Attacks that require the user to run an already-compromised Node process
- DoS via extremely large local networks (this tool is designed for home networks)

## Hardening Guidance for Operators

- Set `HOMESCAN_SUBNET` to your actual home subnet; the server validates this
  at startup and refuses values containing shell metacharacters.
- Run the MCP server as an unprivileged user. `arp` and `ping` do not require root.
- If exporting to Obsidian, treat generated notes as untrusted input until
  reviewed — device names and manufacturers come from local DNS and OUI data.
