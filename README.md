# MCP Homescan Server

[![npm version](https://img.shields.io/npm/v/mcp-homescan.svg)](https://www.npmjs.com/package/mcp-homescan)
[![CI](https://github.com/aplaceforallmystuff/mcp-homescan/actions/workflows/ci.yml/badge.svg)](https://github.com/aplaceforallmystuff/mcp-homescan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)

MCP server for home network discovery and security scanning. Discovers devices on your local network, identifies manufacturers, flags potential security concerns, and exports to Obsidian inventory format.

## Why Use This?

If you're managing a home or small office network, this MCP server lets you:

- **Discover all devices** - Find everything connected to your network via ARP table scanning
- **Identify manufacturers** - Automatic MAC address to manufacturer lookup
- **Flag security concerns** - Identify unknown or potentially risky devices (IoT from certain regions, etc.)
- **Track changes** - Detect new or removed devices between scans
- **Document your network** - Export to markdown for Obsidian or other documentation systems

## Features

| Category | Capabilities |
|----------|-------------|
| **Discovery** | ARP-based network scanning, ping sweep for comprehensive discovery |
| **Identification** | MAC address manufacturer lookup, device categorization |
| **Security** | Flag unknown devices, identify potential IoT risks |
| **Change Detection** | Compare scans, track new/removed devices |
| **Export** | Markdown and JSON formats, Obsidian-compatible inventory |

## Prerequisites

- Node.js 18+
- macOS or Linux (uses `arp` command)
- Network access to local subnet

## Installation

### Using npm (Recommended)

```bash
npx mcp-homescan
```

Or install globally:

```bash
npm install -g mcp-homescan
```

### From Source

```bash
git clone https://github.com/aplaceforallmystuff/mcp-homescan.git
cd mcp-homescan
npm install
npm run build
```

## Configuration

### For Claude Desktop

Add to your Claude Desktop config file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "homescan": {
      "command": "npx",
      "args": ["-y", "mcp-homescan"],
      "env": {
        "HOMESCAN_SUBNET": "192.168.1"
      }
    }
  }
}
```

### For Claude Code

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "homescan": {
      "command": "npx",
      "args": ["-y", "mcp-homescan"],
      "env": {
        "HOMESCAN_SUBNET": "192.168.1"
      }
    }
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HOMESCAN_SUBNET` | Network subnet to scan (e.g., `192.168.1`) | `192.168.1` |
| `SHODAN_API_KEY` | Optional Shodan API key for vulnerability lookups | - |

## Usage Examples

### Network Discovery
> "Scan my home network for devices"

> "What devices are on my network?"

> "Refresh the network scan and show all devices"

### Device Investigation
> "What's the device at 192.168.1.34?"

> "Look up the manufacturer for MAC address aa:bb:cc:dd:ee:ff"

### Security Review
> "Show me any flagged devices on my network"

> "Are there any unknown devices I should investigate?"

### Change Tracking
> "Have any new devices appeared since the last scan?"

> "Show me what's changed on my network"

### Documentation
> "Export my network inventory to markdown"

> "Generate a network report"

## Available Tools

| Tool | Description |
|------|-------------|
| `homescan_discover` | Discover all devices on the local network |
| `homescan_device` | Get details for a specific device by IP |
| `homescan_mac_lookup` | Look up manufacturer from MAC address |
| `homescan_report` | Generate comprehensive network discovery report |
| `homescan_export` | Export devices to markdown or JSON format |
| `homescan_diff` | Compare current scan to previous, show changes |
| `homescan_flagged` | List devices flagged for security review |

## Development

```bash
# Watch mode for development
npm run watch

# Build TypeScript
npm run build

# Run locally
node dist/index.js
```

## Troubleshooting

### "No devices found"
Ensure you're on the same network segment and the subnet is configured correctly. Try running with `refresh: true` to perform a ping sweep first.

### "Permission denied" errors
The ARP table may require elevated permissions on some systems. Try running with `sudo` if needed.

### Devices missing from scan
Some devices may not respond to ARP queries. Use `homescan_discover` with `refresh: true` to ping sweep the network first.

### Wrong subnet
Check your network configuration and update `HOMESCAN_SUBNET` to match your local network (common values: `192.168.1`, `192.168.0`, `10.0.0`).

## Security Notes

- This tool only scans your local network
- No data is sent externally (unless Shodan API is configured)
- Flagged devices are recommendations only - verify before taking action

## Roadmap

- [ ] Shodan integration for CVE lookups
- [ ] Pi-hole DNS query correlation
- [ ] Port scanning (nmap-lite)
- [ ] Baseline storage and alerting
- [ ] Router DHCP lease integration

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT - see [LICENSE](LICENSE) for details.

## Links

- [Model Context Protocol](https://modelcontextprotocol.io)
- [MCP Specification](https://spec.modelcontextprotocol.io)
- [GitHub Repository](https://github.com/aplaceforallmystuff/mcp-homescan)
