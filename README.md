# JeremiahPortGuard v6

Version 6 adds first-install GUI autostart, printable/viewable guide, service-mode switching using the simple case-insensitive `PORTGUIDE` confirmation, a restore-GUI command/menu entry, conflict alerts with suppression, and a local-only status/instructions page on `127.0.0.1:23458`. Existing registry, resource governor, and WesternHillsAgent behavior are preserved.

The local web page is informational only and binds to IPv4 loopback. It does not expose the service to the LAN/WAN.

# JeremiahPortGuard v0.3.0

JeremiahPortGuard is a Qt 6 / C++ local port registry and Linux listener observer for the Manjaro T14. It uses SQLite as the authoritative registry and does not open a network listener in this version.

## v0.3.0 changes

- Adds `development_gate.json`, a portable machine-readable development contract for tracker project `201`.
- Before each new development version, ChatGPT/development tooling must run `/opt/sep13/tracker.sh 201` exactly once.
- If the tracker output contains `IT IS TIME TO MAKE SURE THIS PROJECT IS ON GITHUB NOW.`, feature development stops until `https://github.com/we6jbo/JeremiahPortGuard` is verified/pushed and `987324987.txt` exists on `master`.
- The installer deliberately does **not** run the tracker, preventing one version from decrementing the counter twice.

- Uses the approved September 13, 2026 T14 resource report as the immutable baseline.
- 99% health or better remains full throttle: being 1% below baseline does not reduce work.
- Requires sustained degradation before throttling; one or two 5-second samples do not slow the program.
- Around 5% below baseline, it considers whether JeremiahPortGuard itself is contributing before applying meaningful throttling.
- Resource health is based primarily on remaining CPU, RAM, disk, and load headroom relative to the approved baseline, with battery-drain and thermal safeguards.
- The resource monitor stays at a lightweight 5-second cadence so recovery is detected quickly.
- The heavier listener scan is now actually paced by the governor: 30s at full speed, then 45s/90s/180s/300s as pressure rises, with a maximum 600-second pause interval under severe pressure.
- Existing Linux listeners remain OBSERVED_UNMANAGED and are never claimed automatically.
- Ports 23458 and 23459 remain policy-reserved only; JeremiahPortGuard does not listen on them.
- Existing v1 SQLite databases are migrated in place with new load and battery-drain columns.

## Baseline source

The baseline was measured September 13, 2026. Plugged-in averages include CPU 12.34%, RAM 37.51%, root filesystem 63.61% used, and 1-minute load 1.192. Unplugged averages include CPU 17.59%, RAM 38.26%, root filesystem 63.70% used, and 1-minute load 1.791. The unplugged test changed battery from 100.0% to 97.3% over 413.1 seconds, approximately 0.392 percentage points per minute.

`resource_baseline.json` is copied into the machine-wide JeremiahPortGuard data directory during installation and is the approved reference. The program may observe later system behavior, but v0.3.0 does not silently replace this baseline.

## Network policy

This version does not create a client/server or bind to any port. The supplied project contract requires explicit permission plus authorization code `3team` before a client/server is created.

TG/AKA provenance identifier: `TG333041`.

## Development tracker gate

`development_gate.json` is part of the source tree so project snapshots sent to an AI retain the GitHub gate configuration. The development-time tracker is not a runtime resource of JeremiahPortGuard and is not called by the installer. One tracker decrement corresponds to one new development version.

## v4 WesternHillsAgent integration

Version 0.4.0 adds an authorized loopback-only client integration with WesternHillsAgent.
The user supplied authorization code `3team` before this connection capability was added.
JeremiahPortGuard does not open a new listener for this integration.

WesternHillsAgent protocol used by this version:

- Primary: `127.0.0.1:32767`
- Secondary: `127.0.0.1:32766`
- TCP over IPv4 loopback
- NDJSON framing
- Protocol version 1

JeremiahPortGuard performs the six documented informational request types:
`ping`, `identity`, `status_request`, `port_status`, `capabilities`, and
`network_specifications`. `port_status` and `network_specifications` are sent on
the secondary channel.

A successful session satisfies the recurring contact requirement for six hours.
If the agent cannot be reached, JeremiahPortGuard retries in ten minutes rather
than waiting six hours. Listener discovery can also request an earlier session
when it encounters an unresolved owner/executable identity. The same unresolved
condition is not repeatedly sent every scan.

Machine-readable status is written to:

`/var/lib/JeremiahPortGuard/western_hills_agent_status.json`

The SQLite database also records each attempt in `western_hills_contacts`.
This integration uses only the documented informational request types and does
not enable remote-control or arbitrary-command execution.


## v6 WesternHillsAgent diagnostic context

Every WesternHillsAgent informational request now carries a bounded `diagnosticContext` object. It includes the triggering reason, recent relevant port-registry events, policy-port state, governor/resource state, alert suppression state, and detected JeremiahPortGuard executable instances. Policy-reserved and managed-port conflicts now cause an uncertainty consultation, and multiple JeremiahPortGuard executable instances can also trigger a consultation. The context deliberately excludes packet payloads, credentials, browser history, clipboard contents, keystrokes, unrelated files, and unrelated process memory.
