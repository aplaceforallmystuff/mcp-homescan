/**
 * Network discovery utilities
 * Handles ARP scanning, MAC lookups, and device fingerprinting
 */

import { exec, execFile } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

const SUBNET_RE = /^(?:\d{1,3}\.){2}\d{1,3}$/;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function octetsValid(parts: string[]): boolean {
  return parts.every((p) => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

/**
 * Validate a /24 subnet prefix like "192.168.1".
 * Rejects shell metacharacters by construction.
 */
export function isValidSubnet(subnet: string): boolean {
  if (!SUBNET_RE.test(subnet)) return false;
  return octetsValid(subnet.split("."));
}

/**
 * Validate a full IPv4 address like "192.168.1.42".
 */
export function isValidIPv4(ip: string): boolean {
  if (!IPV4_RE.test(ip)) return false;
  return octetsValid(ip.split("."));
}

/**
 * Normalise a MAC address to canonical lower-case, colon-separated,
 * zero-padded form: "0:50:56:ab:cd:ef" -> "00:50:56:ab:cd:ef".
 *
 * macOS/Linux `arp -a` strips leading zeros from each octet, which would
 * otherwise cause OUI prefix lookups to silently miss.
 *
 * Returns the input unchanged if it doesn't look like a MAC.
 */
export function normaliseMac(mac: string): string {
  const parts = mac.toLowerCase().split(":");
  if (parts.length !== 6) return mac.toLowerCase();
  if (!parts.every((p) => /^[0-9a-f]{1,2}$/.test(p))) return mac.toLowerCase();
  return parts.map((p) => p.padStart(2, "0")).join(":");
}

export interface NetworkDevice {
  ip: string;
  mac: string;
  manufacturer?: string;
  hostname?: string;
  firstSeen?: string;
  lastSeen?: string;
}

export interface ArpEntry {
  ip: string;
  mac: string;
  interface: string;
  complete: boolean;
}

/**
 * Parse macOS/Linux arp -a output
 */
export function parseArpOutput(output: string): ArpEntry[] {
  const entries: ArpEntry[] = [];
  const lines = output.split("\n");

  for (const line of lines) {
    // macOS format: ? (192.168.1.1) at 88:de:7c:e2:cc:c0 on en0 ifscope [ethernet]
    // Linux format: ? (192.168.1.1) at 88:de:7c:e2:cc:c0 [ether] on eth0
    const macosMatch = line.match(
      /\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)\s+on\s+(\w+)/i
    );

    if (macosMatch) {
      const [, ip, mac, iface] = macosMatch;
      // Skip incomplete entries and multicast
      if (mac && mac !== "(incomplete)" && !ip.startsWith("224.") && !ip.startsWith("239.")) {
        entries.push({
          ip,
          mac: normaliseMac(mac),
          interface: iface,
          complete: true,
        });
      }
    }
  }

  return entries;
}

/**
 * Get ARP table from system
 */
export async function getArpTable(): Promise<ArpEntry[]> {
  try {
    const { stdout } = await execAsync("arp -a");
    return parseArpOutput(stdout);
  } catch (error) {
    throw new Error(`Failed to get ARP table: ${error}`);
  }
}

/**
 * MAC address vendor lookup using local OUI database
 * Common prefixes for home network devices
 */
const MAC_VENDORS: Record<string, string> = {
  // Apple
  "00:8a:76": "Apple",
  "a0:ce:c8": "Apple",
  "ac:de:48": "Apple",
  "f0:18:98": "Apple",

  // Networking
  "88:de:7c": "Mitrastar Technology (ISP Router)",
  "00:11:32": "Synology",
  "dc:a6:32": "Raspberry Pi Foundation",
  "b8:27:eb": "Raspberry Pi Foundation",
  "e4:5f:01": "Raspberry Pi Foundation",

  // Smart Home
  "e4:24:6c": "Xiaomi",
  "58:d3:49": "Google (Nest/Chromecast)",
  "f4:f5:d8": "Google",
  "54:60:09": "Google",

  // Entertainment
  "48:e1:5c": "Samsung",
  "b8:8a:ec": "Humax",
  "00:09:b0": "Onkyo",
  "00:04:4b": "Nvidia",

  // IoT / Chinese Manufacturers
  "bc:74:4b": "China Mobile",
  "7c:49:eb": "Xiaomi",
  "28:6c:07": "Xiaomi",
  "64:90:c1": "Xiaomi",
  "78:11:dc": "Xiaomi",

  // Amazon
  "44:65:0d": "Amazon",
  "68:54:fd": "Amazon",
  "a0:02:dc": "Amazon",

  // Gaming
  "7c:bb:8a": "Nintendo",
  "00:1a:e8": "Nintendo",
  "00:22:aa": "Sony PlayStation",
  "00:24:8d": "Sony PlayStation",
  "00:1d:d8": "Microsoft Xbox",

  // Networking Equipment
  "00:18:0a": "ASUS",
  "1c:87:2c": "ASUS",
  "00:14:bf": "Linksys",
  "c8:d7:19": "Cisco-Linksys",
  "00:1e:58": "D-Link",
  "00:26:5a": "D-Link",
  "e0:46:9a": "Netgear",
  "a4:2b:8c": "Netgear",
  "00:24:b2": "Netgear",
  "30:b5:c2": "TP-Link",
  "50:c7:bf": "TP-Link",
  "ec:08:6b": "TP-Link",

  // Computers
  "00:0c:29": "VMware",
  "00:50:56": "VMware",
  "08:00:27": "VirtualBox",
  "52:54:00": "QEMU/KVM",
};

/**
 * Look up manufacturer from MAC address
 */
export function lookupMacVendor(mac: string): string | undefined {
  const prefix = mac.toLowerCase().substring(0, 8);
  return MAC_VENDORS[prefix];
}

/**
 * Check if MAC is a private/randomized address
 * Private MACs have the locally administered bit set (second hex char is 2, 6, A, or E)
 */
export function isPrivateMac(mac: string): boolean {
  const secondChar = mac.charAt(1).toLowerCase();
  return ["2", "6", "a", "e"].includes(secondChar);
}

/**
 * Discover all devices on the network
 */
export async function discoverDevices(): Promise<NetworkDevice[]> {
  const arpEntries = await getArpTable();
  const devices: NetworkDevice[] = [];
  const seen = new Set<string>();

  for (const entry of arpEntries) {
    // Deduplicate by MAC (same device may appear on multiple interfaces)
    if (seen.has(entry.mac)) continue;
    seen.add(entry.mac);

    // Skip link-local addresses
    if (entry.ip.startsWith("169.254.")) continue;
    if (entry.ip.startsWith("192.168.64.")) continue; // VM bridge

    const manufacturer = lookupMacVendor(entry.mac);
    const isPrivate = isPrivateMac(entry.mac);

    devices.push({
      ip: entry.ip,
      mac: entry.mac,
      manufacturer: manufacturer || (isPrivate ? "Private/Randomized MAC" : "Unknown"),
      lastSeen: new Date().toISOString(),
    });
  }

  // Sort by IP address
  devices.sort((a, b) => {
    const aOctets = a.ip.split(".").map(Number);
    const bOctets = b.ip.split(".").map(Number);
    for (let i = 0; i < 4; i++) {
      if (aOctets[i] !== bOctets[i]) return aOctets[i] - bOctets[i];
    }
    return 0;
  });

  return devices;
}

/**
 * Get device details for a specific IP
 */
export async function getDeviceDetails(ip: string): Promise<NetworkDevice | null> {
  const devices = await discoverDevices();
  return devices.find((d) => d.ip === ip) || null;
}

/**
 * Ping sweep to populate ARP cache (finds devices not in cache)
 */
export async function pingSweep(subnet: string = "192.168.1"): Promise<void> {
  if (!isValidSubnet(subnet)) {
    throw new Error(
      `Invalid subnet: ${JSON.stringify(subnet)}. Expected format: "A.B.C" (e.g. "192.168.1")`
    );
  }

  const promises: Promise<void>[] = [];

  for (let i = 1; i <= 254; i++) {
    const ip = `${subnet}.${i}`;
    promises.push(
      execFileAsync("ping", ["-c", "1", "-W", "100", ip], { timeout: 1000 })
        .then(() => {})
        .catch(() => {})
    );
  }

  // Run in batches to avoid overwhelming the network
  const batchSize = 50;
  for (let i = 0; i < promises.length; i += batchSize) {
    await Promise.all(promises.slice(i, i + batchSize));
  }
}
