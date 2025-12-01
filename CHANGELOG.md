# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
