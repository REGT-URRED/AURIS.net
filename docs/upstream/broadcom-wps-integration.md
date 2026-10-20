> **Estado:** publicado como <https://github.com/qkaiser/broadcom-wps/issues/28>
> (2026-10-20). Este archivo es la fuente del cuerpo del issue; si se edita,
> volver a publicarlo o comentar la actualización.

## Context

AURIS.net is an MIT-licensed, Wifite-style 802.11 audit framework (Python,
Linux, offline field bundle) with a phase engine, RoE gating and
evidence/report generation: <https://github.com/REGT-URRED/AURIS.net>

The Broadcom WPS Monitor research is directly relevant to the CPE fleet we
assess, so we integrated the toolkit instead of reimplementing it. This follows
the same direction raised in #27 for Wifit3, from a project that already uses a
Wifite-style pipeline.

## What we integrated

- `research/broadcom-wps/` vendors `broadcom_fingerprint.py`,
  `broadcom_wps_monitor.yar`, the upstream README and the MIT license at commit
  `0727296`, unmodified.
- `VENDOR.md` records provenance, license, usage and claim boundaries.
- New CLI entry point:
  `sudo auris broadcom --interface wlan0mon --ssid "<SSID>"`
  (prefers `uv run --with scapy`, falls back to Python 3.11 + scapy).
- The field bundle (`scripts/pack.sh`) ships the scripts and YARA rules;
  per-run artifacts (`result.json`, `traffic.pcap`) stay out of version control.
- Tests cover the vendored files, rule names, script compilation and CLI
  wiring. No RF is emitted during tests.

## Why it may be useful for this research

The fingerprint runs inside a pipeline that already owns monitor-mode
lifecycle (create/adopt/restore), RoE gating, evidence directories and
MITRE-mapped reports, and can correlate the assessment with WPS phase results
(Pixie Dust, PIN class, lockout) and vendor intelligence. Field teams can run
it fully offline.

We make no exploit claim: `LIKELY_VULNERABLE` is treated as
implementation-family evidence, exactly as the upstream README states.

## Proposal

1. Add an "Integrations" / "Downstream projects" section to the README listing
   projects that vendor or wrap this toolkit.
2. We are happy to send a PR with that section (one table row plus link), or to
   keep this as an issue if you prefer not to advertise integrations.

Would you accept such a PR? We can also contribute fingerprint runs and PCAPs
for devices already on the affected list, if that is useful.
