# Roadmap

Planned work for `mcp-homescan`, grouped by effort. Items within a group
are roughly ordered by impact.

## Medium (1–2 hours each)

### Swap hand-rolled OUI table for real IEEE database

The current `MAC_VENDORS` object in `src/discovery.ts` has ~60 entries. The
IEEE OUI registry has ~35,000. On real home networks this means most
devices resolve to `Unknown`, which in turn floods the `homescan_flagged`
output with false positives.

- Option A: depend on `node-oui` or `oui` npm package
- Option B: download IEEE `oui.csv` at build time, bundle as compressed JSON

Acceptance: a device with a TP-Link, Ubiquiti, or Google phone OUI resolves
correctly without a code change.

### SQLite persistence for scan history

`lastScanResults` currently lives only in memory. `homescan_diff` can't
detect a device that joined while the server was down. Persisting scans
to a small SQLite file (using `better-sqlite3`) would unlock:

- Long-term baseline
- "First seen" / "last seen" per device (already in the type, unused)
- Alerting on devices that disappear

Acceptance: restart the server, run `homescan_diff`, get meaningful output.

### Rate-limit and consent on `pingSweep`

254 concurrent-in-batches pings is fine for a /24 home LAN but surprises
users on larger networks. Add:

- Per-scan concurrency ceiling (configurable, default 20)
- Cooldown between sweeps (default 60 s)
- A one-time consent prompt surfaced via a resource / prompt

Acceptance: two back-to-back sweep calls return a clear "too soon" error
rather than actually re-scanning.

## Bigger (half a day+ each)

### mDNS / reverse-DNS for hostname population

The `NetworkDevice.hostname` field is declared but never set. With hostnames
the Obsidian export filenames become readable (`living-room-tv.md` instead
of `Samsung - 192.168.1.42.md`). mDNS for Apple/Bonjour devices, reverse
DNS for the rest.

### Optional `nmap` wrapper — deliver on "vulnerability scanning"

The package description and keywords reference vulnerability scanning, which
the current implementation does not do. An opt-in `homescan_probe` tool
wrapping a minimal `nmap` invocation (`-sV` on common ports, with explicit
user consent) would close the gap. Needs careful shell-safety treatment —
same lesson as the SUBNET fix.

### CI: run the test suite

`npm test` exists but is not yet in `.github/workflows/ci.yml`. Add a
`- name: Test` step after the existing type-check. Trivial change, listed
here because it was blocked by a security hook in the session that created
this roadmap.

### Observability

Structured logging (JSON lines to stderr) with a configurable level, so that
when a user reports "no devices found" we can see whether `arp` returned
nothing or the parser dropped everything.

## Explicitly not planned

- Shodan integration — the env var was removed because it was dead code.
  The tool is designed for local network scanning; CVE lookup is a
  different product.
- Cloud sync / multi-host aggregation — out of scope for a home-network
  tool.

## Completed

See [CHANGELOG.md](CHANGELOG.md) for what's already shipped.
