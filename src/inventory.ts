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

  const assessment = assessDevice(device);
  if (assessment.flagged) {
    lines.push("security_review: true");
    lines.push(`risk_level: ${assessment.risk}`);
  }

  lines.push(`notes: "Auto-discovered by mcp-homescan"`);
  lines.push("---");

  return lines.join("\n");
}

export type RiskLevel = "info" | "low" | "medium";

export interface DeviceAssessment {
  flagged: boolean;
  risk: RiskLevel;
  reasons: string[];
}

/**
 * Determine device category from manufacturer
 */
export function categorizeDevice(device: NetworkDevice): string {
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
 * Assess a device for review-worthiness based on observable properties,
 * not vendor nationality.
 *
 * Signals:
 *   - Unknown manufacturer: MAC OUI did not resolve; operator can't confirm purpose.
 *   - Smart Home / IoT class: devices in this class (any vendor) commonly phone
 *     home to cloud services, have weaker update cadence, and appear in
 *     botnet exploitation datasets (Mirai etc.). Review applies equally to
 *     Amazon, Google, Xiaomi, Samsung, TP-Link smart, etc.
 *   - Private/randomized MAC: informational — identity obscured by design
 *     (e.g. iOS/macOS privacy). Not a risk in itself.
 */
export function assessDevice(device: NetworkDevice): DeviceAssessment {
  const reasons: string[] = [];
  let risk: RiskLevel = "info";
  let flagged = false;

  const category = categorizeDevice(device);

  if (device.manufacturer === "Unknown") {
    reasons.push(
      "Unknown manufacturer — MAC OUI unresolved; confirm device identity"
    );
    risk = "medium";
    flagged = true;
  }

  if (category === "Smart Home") {
    reasons.push(
      "IoT/Smart Home class — review cloud connectivity, update cadence, and network isolation"
    );
    if (risk === "info") risk = "low";
    flagged = true;
  }

  if (device.manufacturer === "Private/Randomized MAC") {
    reasons.push(
      "Locally-administered MAC — identity obscured by design (informational, not a risk)"
    );
    // informational only; do not flag unless already flagged for another reason
  }

  return { flagged, risk, reasons };
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

  const assessment = assessDevice(device);
  if (assessment.flagged) {
    content += `
## Security Review

Flagged for review (risk: **${assessment.risk}**):

${assessment.reasons.map((r) => `- ${r}`).join("\n")}

General hardening steps for any reviewed device:
- Monitor DNS queries via Pi-hole or equivalent
- Isolate IoT devices on a separate VLAN
- Block unnecessary outbound connections at the firewall
- Keep firmware current; subscribe to vendor CVE feeds
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

  // Flag devices needing attention (behavior/category-based)
  const assessed = devices
    .map((d) => ({ device: d, assessment: assessDevice(d) }))
    .filter((x) => x.assessment.flagged);

  if (assessed.length > 0) {
    report += `
## Devices Requiring Review

Flagging is based on observable properties (unknown vendor, IoT device class),
not vendor nationality.

| IP | MAC | Manufacturer | Risk | Reason |
|----|-----|--------------|------|--------|
`;
    for (const { device, assessment } of assessed) {
      report += `| ${device.ip} | ${device.mac} | ${device.manufacturer || "Unknown"} | ${assessment.risk} | ${assessment.reasons.join("; ")} |\n`;
    }
  }

  return report;
}
