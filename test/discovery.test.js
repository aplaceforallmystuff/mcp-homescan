import { test } from "node:test";
import assert from "node:assert/strict";

import {
  isValidSubnet,
  isValidIPv4,
  isPrivateMac,
  normaliseMac,
  parseArpOutput,
  lookupMacVendor,
} from "../dist/discovery.js";

test("isValidSubnet accepts valid /24 prefixes", () => {
  assert.equal(isValidSubnet("192.168.1"), true);
  assert.equal(isValidSubnet("10.0.0"), true);
  assert.equal(isValidSubnet("172.16.254"), true);
  assert.equal(isValidSubnet("0.0.0"), true);
  assert.equal(isValidSubnet("255.255.255"), true);
});

test("isValidSubnet rejects shell metacharacters", () => {
  assert.equal(isValidSubnet("192.168.1; rm -rf /"), false);
  assert.equal(isValidSubnet("192.168.1 && curl evil"), false);
  assert.equal(isValidSubnet("192.168.1|whoami"), false);
  assert.equal(isValidSubnet("$(whoami)"), false);
  assert.equal(isValidSubnet("`whoami`"), false);
  assert.equal(isValidSubnet("192.168.1\n"), false);
});

test("isValidSubnet rejects malformed input", () => {
  assert.equal(isValidSubnet("192.168"), false);
  assert.equal(isValidSubnet("192.168.1.1"), false);
  assert.equal(isValidSubnet("256.1.1"), false);
  assert.equal(isValidSubnet("192.168.-1"), false);
  assert.equal(isValidSubnet("192.168.abc"), false);
  assert.equal(isValidSubnet(""), false);
});

test("isValidIPv4 accepts valid addresses", () => {
  assert.equal(isValidIPv4("192.168.1.42"), true);
  assert.equal(isValidIPv4("10.0.0.1"), true);
  assert.equal(isValidIPv4("0.0.0.0"), true);
  assert.equal(isValidIPv4("255.255.255.255"), true);
});

test("isValidIPv4 rejects injection and out-of-range", () => {
  assert.equal(isValidIPv4("192.168.1.42; curl evil"), false);
  assert.equal(isValidIPv4("999.1.1.1"), false);
  assert.equal(isValidIPv4("192.168.1"), false);
  assert.equal(isValidIPv4("192.168.1.1.1"), false);
  assert.equal(isValidIPv4("192.168.1.-1"), false);
  assert.equal(isValidIPv4(""), false);
});

test("isPrivateMac identifies locally-administered addresses", () => {
  // Second nibble 2/6/a/e = locally administered
  assert.equal(isPrivateMac("02:00:00:00:00:00"), true);
  assert.equal(isPrivateMac("06:00:00:00:00:00"), true);
  assert.equal(isPrivateMac("0a:00:00:00:00:00"), true);
  assert.equal(isPrivateMac("0e:00:00:00:00:00"), true);
  // 0/4/8/c = globally unique
  assert.equal(isPrivateMac("00:00:00:00:00:00"), false);
  assert.equal(isPrivateMac("04:00:00:00:00:00"), false);
  assert.equal(isPrivateMac("a0:ce:c8:00:00:00"), false);
});

test("isPrivateMac works after normalisation (zero-padded)", () => {
  // macOS arp strips leading zero: "2:0:0:0:0:0" should still be detected
  // once passed through normaliseMac
  assert.equal(isPrivateMac(normaliseMac("2:0:0:0:0:0")), true);
  assert.equal(isPrivateMac(normaliseMac("a:0:0:0:0:0")), true);
});

test("normaliseMac pads octets and lowercases", () => {
  assert.equal(normaliseMac("0:50:56:AB:CD:EF"), "00:50:56:ab:cd:ef");
  assert.equal(normaliseMac("a:b:c:d:e:f"), "0a:0b:0c:0d:0e:0f");
  assert.equal(normaliseMac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff");
  assert.equal(normaliseMac("00:11:22:33:44:55"), "00:11:22:33:44:55");
});

test("normaliseMac leaves garbage input alone (but lowercased)", () => {
  assert.equal(normaliseMac("not-a-mac"), "not-a-mac");
  assert.equal(normaliseMac("00:11:22"), "00:11:22");
  assert.equal(normaliseMac("00:11:22:33:44:GG"), "00:11:22:33:44:gg");
});

test("lookupMacVendor finds canonical prefixes", () => {
  assert.equal(lookupMacVendor("00:50:56:ab:cd:ef"), "VMware");
  assert.equal(lookupMacVendor("a0:ce:c8:11:22:33"), "Apple");
  assert.equal(lookupMacVendor("b8:27:eb:00:00:00"), "Raspberry Pi Foundation");
});

test("lookupMacVendor returns undefined for unknown prefix", () => {
  assert.equal(lookupMacVendor("aa:bb:cc:dd:ee:ff"), undefined);
});

test("parseArpOutput extracts macOS format entries", () => {
  const output = `
? (192.168.1.1) at 88:de:7c:e2:cc:c0 on en0 ifscope [ethernet]
? (192.168.1.42) at a0:ce:c8:11:22:33 on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
`;
  const entries = parseArpOutput(output);
  // Multicast (224.x) filtered; incomplete filtered
  assert.equal(entries.length, 2);
  assert.equal(entries[0].ip, "192.168.1.1");
  assert.equal(entries[0].mac, "88:de:7c:e2:cc:c0");
  assert.equal(entries[1].ip, "192.168.1.42");
  assert.equal(entries[1].mac, "a0:ce:c8:11:22:33");
});

test("parseArpOutput normalises stripped zeros from macOS arp", () => {
  // macOS prints `0:50:56` not `00:50:56`
  const output = `? (192.168.1.1) at 0:50:56:ab:cd:ef on en0 ifscope [ethernet]`;
  const entries = parseArpOutput(output);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].mac, "00:50:56:ab:cd:ef");
});
