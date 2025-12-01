/**
 * Obsidian inventory integration
 * Exports discovered devices to Obsidian vault format
 */

import { NetworkDevice } from "./discovery.js";

export interface InventoryItem {
  filename: string;
  content: string;
}

/**
 * Generate frontmatter for inventory item
 */
function generateFrontmatter(device: NetworkDevice, category: string): string {
  const lines = [
    "---",
    "inventory_type: equipment",
    `category: ${category}`,
    "status: active",
    "acquired:",
    "cost:",
    `ip_address: ${device.ip}`,
    `mac_address: ${device.mac}`,
    `manufacturer: ${device.manufacturer || "Unknown"}`,
  ];

  // Flag unknown/suspicious devices for security review
  if (
    device.manufacturer?.includes("Xiaomi") ||
    device.manufacturer?.includes("China") ||
    device.manufacturer === "Unknown"
  ) {
    lines.push("security_review: true");
  }

  lines.push(`notes: "Auto-discovered by mcp-homescan"`);
  lines.push("---");

  return lines.join("\n");
}

/**
 * Determine device category from manufacturer
 */
function categorizeDevice(device: NetworkDevice): string {
  const mfr = device.manufacturer?.toLowerCase() || "";

  if (mfr.includes("apple")) return "Computing";
  if (mfr.includes("synology")) return "Networking";
  if (mfr.includes("raspberry")) return "Computing";
  if (mfr.includes("router") || mfr.includes("mitrastar")) return "Networking";
  if (mfr.includes("google") || mfr.includes("nest")) return "Smart Home";
  if (mfr.includes("xiaomi")) return "Smart Home";
  if (mfr.includes("amazon") || mfr.includes("alexa")) return "Smart Home";
  if (mfr.includes("samsung") || mfr.includes("humax") || mfr.includes("sony"))
    return "Entertainment";
  if (mfr.includes("nintendo") || mfr.includes("playstation") || mfr.includes("xbox"))
    return "Entertainment";
  if (mfr.includes("vm") || mfr.includes("virtual")) return "Virtual";

  return "Unknown";
}

/**
 * Generate a safe filename from device info
 */
function generateFilename(device: NetworkDevice): string {
  let name: string;

  if (device.hostname) {
    name = device.hostname;
  } else if (device.manufacturer && device.manufacturer !== "Unknown") {
    name = `${device.manufacturer} - ${device.ip}`;
  } else {
    name = `Unknown Device - ${device.ip}`;
  }

  // Sanitize for filesystem
  return name.replace(/[<>:"/\\|?*]/g, "-").substring(0, 100) + ".md";
}

/**
 * Generate markdown content for a device
 */
function generateMarkdown(device: NetworkDevice): string {
  const category = categorizeDevice(device);
  const frontmatter = generateFrontmatter(device, category);

  const title = device.hostname || device.manufacturer || `Device at ${device.ip}`;

  let content = `${frontmatter}

# ${title}

## Details

**Make/Brand:** ${device.manufacturer || "Unknown"}
**Model:**
**IP Address:** ${device.ip}
**MAC Address:** ${device.mac}

## Notes

Auto-discovered by mcp-homescan on ${new Date().toISOString().split("T")[0]}.
`;

  // Add security warning for flagged devices
  if (
    device.manufacturer?.includes("Xiaomi") ||
    device.manufacturer?.includes("China")
  ) {
    content += `
## Security

This device may communicate with servers outside your control. Consider:
- Monitoring DNS queries via Pi-hole
- Isolating on a separate VLAN
- Blocking unnecessary outbound connections
`;
  }

  return content;
}

/**
 * Export devices to Obsidian inventory format
 */
export function exportToObsidian(devices: NetworkDevice[]): InventoryItem[] {
  return devices.map((device) => ({
    filename: generateFilename(device),
    content: generateMarkdown(device),
  }));
}

/**
 * Generate a summary report of discovered devices
 */
export function generateDiscoveryReport(devices: NetworkDevice[]): string {
  const byCategory: Record<string, NetworkDevice[]> = {};

  for (const device of devices) {
    const category = categorizeDevice(device);
    if (!byCategory[category]) byCategory[category] = [];
    byCategory[category].push(device);
  }

  let report = `# Network Discovery Report

**Date:** ${new Date().toISOString()}
**Total Devices:** ${devices.length}

## Summary by Category

| Category | Count |
|----------|-------|
`;

  for (const [category, categoryDevices] of Object.entries(byCategory).sort()) {
    report += `| ${category} | ${categoryDevices.length} |\n`;
  }

  report += `
## All Devices

| IP | MAC | Manufacturer | Category |
|----|-----|--------------|----------|
`;

  for (const device of devices) {
    const category = categorizeDevice(device);
    report += `| ${device.ip} | ${device.mac} | ${device.manufacturer || "Unknown"} | ${category} |\n`;
  }

  // Flag devices needing attention
  const flagged = devices.filter(
    (d) =>
      d.manufacturer?.includes("Xiaomi") ||
      d.manufacturer?.includes("China") ||
      d.manufacturer === "Unknown" ||
      d.manufacturer === "Private/Randomized MAC"
  );

  if (flagged.length > 0) {
    report += `
## Devices Requiring Review

The following devices have been flagged for security review:

| IP | MAC | Reason |
|----|-----|--------|
`;
    for (const device of flagged) {
      let reason = "Unknown manufacturer";
      if (device.manufacturer?.includes("Xiaomi")) reason = "Xiaomi device - may phone home";
      if (device.manufacturer?.includes("China")) reason = "Chinese manufacturer - verify purpose";
      if (device.manufacturer === "Private/Randomized MAC") reason = "Randomized MAC - could be anything";

      report += `| ${device.ip} | ${device.mac} | ${reason} |\n`;
    }
  }

  return report;
}
