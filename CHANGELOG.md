# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- Validate `HOMESCAN_SUBNET` at startup and reject shell metacharacters; previously a crafted env value could inject commands into the `ping` sweep.
- Switch `ping` invocation from `exec` (shell) to `execFile` (argv) as defense in depth.
- Validate `ip` argument on `homescan_device` tool as IPv4 at the tool boundary.
- Added `SECURITY.md` with vulnerability disclosure policy.

### Changed
- **Breaking (behaviour):** Security flagging is now category/behaviour-based, not vendor-nationality-based. IoT/Smart Home devices are flagged regardless of vendor (Amazon, Google, Xiaomi, Samsung, TP-Link smart, etc. all receive equal review). Removed the "Chinese manufacturer" risk category.
- Risk levels simplified to `info` / `low` / `medium`; private/randomized MACs are now informational rather than flagged.
- Server version now read from `package.json` instead of hardcoded.
- MAC addresses parsed from `arp -a` are now zero-padded; previously macOS's stripped-zero output (`0:50:56:…`) silently missed OUI lookups.

### Added
- Exported `isValidSubnet`, `isValidIPv4`, `normaliseMac` helpers from `discovery.ts`.
- Exported `assessDevice`, `categorizeDevice`, `DeviceAssessment` from `inventory.ts`.
- Unit test suite (`node:test`, no new deps): 21 tests covering validators, MAC normalisation, ARP parsing, and behaviour-based assessment. Run with `npm test`.
- `ROADMAP.md` for planned medium/bigger work.

### Removed
- Unused `SHODAN_API_KEY` env var reference (was declared but never consumed).

## [1.0.0] - 2025-12-20

### Changed
- Bumped to 1.0.0 for npm publication
- Updated @modelcontextprotocol/sdk to ^1.25.1 (security fix)
- Expanded package keywords for npm discoverability
- Added repository, homepage, and bugs URLs to package.json
- Added CONTRIBUTING.md

## [0.1.0] - 2025-11-29

### Added
- Initial release of mcp-homescan
- **Discovery tools:**
  - `homescan_discover` - Scan local network via ARP table
  - `homescan_device` - Get details for specific IP
  - `homescan_mac_lookup` - Look up manufacturer from MAC
- **Reporting tools:**
  - `homescan_report` - Generate markdown network report
  - `homescan_export` - Export to Obsidian inventory format
  - `homescan_diff` - Compare scans for new/removed devices
  - `homescan_flagged` - List devices needing security review
- MAC vendor database with 50+ common home network manufacturers
- Private/randomized MAC detection (Apple privacy feature)
- Security flagging for unknown/Chinese IoT devices
- Obsidian-compatible markdown export with frontmatter
