import { test } from "node:test";
import assert from "node:assert/strict";

import {
  assessDevice,
  categorizeDevice,
  exportToObsidian,
  generateDiscoveryReport,
} from "../dist/inventory.js";

function device(manufacturer, overrides = {}) {
  return {
    ip: "192.168.1.42",
    mac: "aa:bb:cc:dd:ee:ff",
    manufacturer,
    ...overrides,
  };
}

test("categorizeDevice groups vendors into device classes", () => {
  assert.equal(categorizeDevice(device("Apple")), "Computing");
  assert.equal(categorizeDevice(device("Raspberry Pi Foundation")), "Computing");
  assert.equal(categorizeDevice(device("Xiaomi")), "Smart Home");
  assert.equal(categorizeDevice(device("Google (Nest/Chromecast)")), "Smart Home");
  assert.equal(categorizeDevice(device("Amazon")), "Smart Home");
  assert.equal(categorizeDevice(device("Samsung")), "Entertainment");
  assert.equal(categorizeDevice(device("Nintendo")), "Entertainment");
  assert.equal(categorizeDevice(device("VMware")), "Virtual");
  assert.equal(categorizeDevice(device("Unknown")), "Unknown");
});

test("assessDevice flags IoT/Smart Home regardless of vendor nationality", () => {
  // Same risk level for Xiaomi, Google, Amazon — the point is equal treatment
  const xiaomi = assessDevice(device("Xiaomi"));
  const google = assessDevice(device("Google (Nest/Chromecast)"));
  const amazon = assessDevice(device("Amazon"));

  assert.equal(xiaomi.flagged, true);
  assert.equal(google.flagged, true);
  assert.equal(amazon.flagged, true);
  assert.equal(xiaomi.risk, "low");
  assert.equal(google.risk, "low");
  assert.equal(amazon.risk, "low");
});

test("assessDevice does not flag Computing-class devices", () => {
  const apple = assessDevice(device("Apple"));
  const rpi = assessDevice(device("Raspberry Pi Foundation"));
  assert.equal(apple.flagged, false);
  assert.equal(rpi.flagged, false);
});

test("assessDevice flags Unknown manufacturer as medium risk", () => {
  const result = assessDevice(device("Unknown"));
  assert.equal(result.flagged, true);
  assert.equal(result.risk, "medium");
  assert.match(result.reasons[0], /Unknown manufacturer/);
});

test("assessDevice treats private MAC as informational only, not flagged", () => {
  const result = assessDevice(device("Private/Randomized MAC"));
  assert.equal(result.flagged, false);
  // But should still carry an info reason
  assert.ok(result.reasons.some((r) => /Locally-administered/.test(r)));
});

test("assessDevice produces no 'Chinese' or nationality language", () => {
  const vendors = [
    "Xiaomi",
    "China Mobile",
    "Google",
    "Amazon",
    "Samsung",
    "Unknown",
    "Private/Randomized MAC",
  ];
  for (const v of vendors) {
    const result = assessDevice(device(v));
    for (const reason of result.reasons) {
      assert.doesNotMatch(reason, /chinese/i, `vendor=${v} reason=${reason}`);
      assert.doesNotMatch(reason, /china/i, `vendor=${v} reason=${reason}`);
      assert.doesNotMatch(reason, /nationality/i, `vendor=${v} reason=${reason}`);
    }
  }
});

test("exportToObsidian emits security_review frontmatter for flagged devices", () => {
  const items = exportToObsidian([
    device("Xiaomi"),
    device("Apple", { ip: "192.168.1.43", mac: "a0:ce:c8:11:22:33" }),
  ]);
  assert.equal(items.length, 2);
  const xiaomi = items.find((i) => i.content.includes("Xiaomi"));
  const apple = items.find((i) => i.content.includes("Apple"));
  assert.match(xiaomi.content, /security_review: true/);
  assert.match(xiaomi.content, /risk_level: low/);
  assert.doesNotMatch(apple.content, /security_review: true/);
});

test("generateDiscoveryReport has no nationality-based language", () => {
  const report = generateDiscoveryReport([
    device("Xiaomi"),
    device("Amazon", { ip: "192.168.1.43", mac: "44:65:0d:11:22:33" }),
    device("Unknown", { ip: "192.168.1.44", mac: "aa:bb:cc:dd:ee:ff" }),
  ]);
  assert.doesNotMatch(report, /chinese/i);
  assert.doesNotMatch(report, /phone home/i);
  // But it should still flag the devices
  assert.match(report, /Devices Requiring Review/);
  assert.match(report, /not vendor nationality/);
});
