#!/usr/bin/env node
/**
 * MCP Server for Home Network Scanning
 *
 * Discovers devices on the local network, identifies manufacturers,
 * and can export to Obsidian inventory format.
 *
 * Environment variables:
 * - HOMESCAN_SUBNET: Network subnet to scan (default: 192.168.1)
 * - SHODAN_API_KEY: Optional Shodan API key for vulnerability lookups
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

import {
  discoverDevices,
  getDeviceDetails,
  pingSweep,
  lookupMacVendor,
  isPrivateMac,
  NetworkDevice,
} from "./discovery.js";

import {
  exportToObsidian,
  generateDiscoveryReport,
} from "./inventory.js";

// Configuration
const SUBNET = process.env.HOMESCAN_SUBNET || "192.168.1";
const SHODAN_API_KEY = process.env.SHODAN_API_KEY;

// Store last scan results for comparison
let lastScanResults: NetworkDevice[] = [];
let lastScanTime: Date | null = null;

// Define available tools
const TOOLS: Tool[] = [
  {
    name: "homescan_discover",
    description:
      "Discover all devices on the local network using ARP table. Returns IP, MAC address, and manufacturer for each device found.",
    inputSchema: {
      type: "object" as const,
      properties: {
        refresh: {
          type: "boolean",
          description:
            "If true, performs a ping sweep first to populate ARP cache with all active devices. Takes longer but finds more devices.",
        },
      },
      required: [],
    },
  },
  {
    name: "homescan_device",
    description:
      "Get detailed information about a specific device by IP address",
    inputSchema: {
      type: "object" as const,
      properties: {
        ip: {
          type: "string",
          description: "IP address of the device to look up",
        },
      },
      required: ["ip"],
    },
  },
  {
    name: "homescan_mac_lookup",
    description:
      "Look up the manufacturer of a device from its MAC address",
    inputSchema: {
      type: "object" as const,
      properties: {
        mac: {
          type: "string",
          description: "MAC address to look up (format: xx:xx:xx:xx:xx:xx)",
        },
      },
      required: ["mac"],
    },
  },
  {
    name: "homescan_report",
    description:
      "Generate a comprehensive network discovery report in markdown format, including device summary, categories, and security flags",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "homescan_export",
    description:
      "Export discovered devices to Obsidian inventory format. Returns an array of files that can be saved to your vault.",
    inputSchema: {
      type: "object" as const,
      properties: {
        format: {
          type: "string",
          enum: ["markdown", "json"],
          description: "Export format (default: markdown)",
        },
      },
      required: [],
    },
  },
  {
    name: "homescan_diff",
    description:
      "Compare current network scan to the last scan and show new/removed devices",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "homescan_flagged",
    description:
      "List devices flagged for security review (unknown manufacturers, Chinese IoT devices, randomized MACs)",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// Create server instance
const server = new Server(
  {
    name: "mcp-homescan",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle list tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: TOOLS };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "homescan_discover": {
        const refresh = (args as { refresh?: boolean })?.refresh;

        if (refresh) {
          await pingSweep(SUBNET);
        }

        const devices = await discoverDevices();

        // Store for diff comparison
        lastScanResults = devices;
        lastScanTime = new Date();

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  scan_time: lastScanTime.toISOString(),
                  subnet: SUBNET,
                  device_count: devices.length,
                  devices: devices.map((d) => ({
                    ip: d.ip,
                    mac: d.mac,
                    manufacturer: d.manufacturer,
                    is_private_mac: isPrivateMac(d.mac),
                  })),
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "homescan_device": {
        const ip = (args as { ip: string }).ip;
        const device = await getDeviceDetails(ip);

        if (!device) {
          return {
            content: [
              {
                type: "text",
                text: `No device found at ${ip}. It may be offline or not in the ARP cache. Try running homescan_discover with refresh=true first.`,
              },
            ],
          };
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  ...device,
                  is_private_mac: isPrivateMac(device.mac),
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "homescan_mac_lookup": {
        const mac = (args as { mac: string }).mac.toLowerCase();
        const vendor = lookupMacVendor(mac);
        const isPrivate = isPrivateMac(mac);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  mac,
                  manufacturer: vendor || "Unknown",
                  is_private_mac: isPrivate,
                  note: isPrivate
                    ? "This is a locally administered (private/randomized) MAC address, commonly used by Apple devices for privacy."
                    : undefined,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "homescan_report": {
        const devices = await discoverDevices();
        const report = generateDiscoveryReport(devices);

        return {
          content: [
            {
              type: "text",
              text: report,
            },
          ],
        };
      }

      case "homescan_export": {
        const format = (args as { format?: string })?.format || "markdown";
        const devices = await discoverDevices();

        if (format === "json") {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(devices, null, 2),
              },
            ],
          };
        }

        const inventoryItems = exportToObsidian(devices);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  item_count: inventoryItems.length,
                  items: inventoryItems,
                  instructions:
                    "Save each item to your Obsidian vault at 07 Meta/About Jim/Items/",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "homescan_diff": {
        if (!lastScanTime) {
          return {
            content: [
              {
                type: "text",
                text: "No previous scan found. Run homescan_discover first to establish a baseline.",
              },
            ],
          };
        }

        const currentDevices = await discoverDevices();
        const previousMacs = new Set(lastScanResults.map((d) => d.mac));
        const currentMacs = new Set(currentDevices.map((d) => d.mac));

        const newDevices = currentDevices.filter((d) => !previousMacs.has(d.mac));
        const removedDevices = lastScanResults.filter((d) => !currentMacs.has(d.mac));

        // Update stored results
        lastScanResults = currentDevices;
        const previousScanTime = lastScanTime;
        lastScanTime = new Date();

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  previous_scan: previousScanTime.toISOString(),
                  current_scan: lastScanTime.toISOString(),
                  new_devices: newDevices,
                  removed_devices: removedDevices,
                  summary:
                    newDevices.length === 0 && removedDevices.length === 0
                      ? "No changes detected"
                      : `${newDevices.length} new device(s), ${removedDevices.length} removed device(s)`,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "homescan_flagged": {
        const devices = await discoverDevices();

        const flagged = devices.filter(
          (d) =>
            d.manufacturer?.includes("Xiaomi") ||
            d.manufacturer?.includes("China") ||
            d.manufacturer === "Unknown" ||
            d.manufacturer === "Private/Randomized MAC"
        );

        const categorized = flagged.map((d) => {
          let reason = "Unknown manufacturer";
          let risk = "MEDIUM";

          if (d.manufacturer?.includes("Xiaomi")) {
            reason = "Xiaomi device - may send data to Chinese servers";
            risk = "MEDIUM";
          } else if (d.manufacturer?.includes("China")) {
            reason = "Chinese manufacturer - verify device purpose";
            risk = "HIGH";
          } else if (d.manufacturer === "Private/Randomized MAC") {
            reason = "Randomized MAC - device identity obscured";
            risk = "LOW";
          }

          return {
            ...d,
            flag_reason: reason,
            risk_level: risk,
          };
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  flagged_count: categorized.length,
                  total_devices: devices.length,
                  devices: categorized,
                  recommendations: [
                    "Review each flagged device to confirm its purpose",
                    "Check Pi-hole logs for suspicious DNS queries",
                    "Consider isolating IoT devices on a separate VLAN",
                    "Block unnecessary outbound connections at the firewall",
                  ],
                },
                null,
                2
              ),
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text",
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("mcp-homescan server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
