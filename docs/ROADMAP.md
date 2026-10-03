# Roadmap

## 0.1 source preview

- Rust engine, current-user daemon and CLI.
- Hash detections, optional YARA, conservative script heuristics.
- Native after-change monitoring and sampled processes/network metadata.
- Quick/full/custom scans, progress, control and interval schedules.
- Encrypted quarantine, deliberate restore/allow/delete actions.
- Authenticated local bridge, React/Tauri desktop and Astro website.

## Before a stable release

- Independent audit of file operations, ACLs, IPC, updater and native dependencies.
- Vetted signature corpus, reproducible false-positive/detection benchmarks, licenses and feed ownership.
- Handle-relative containment, platform file identity, journaled crash recovery, bounded disk quotas and quarantine recovery UI.
- Restrict native parsers/YARA to sandboxed workers with hard CPU/memory budgets.
- Continue hardening watched-folder reconciliation under adversarial churn; network filesystems and missed process activity need dedicated platform work. Version 0.1.3 adds overflow recovery, bounded workers, retries and monitoring health; see [its limits](REALTIME.md).
- Persist calendar/time-zone schedules, missed-run policy and scan checkpoints across restarts.
- Package/sign GUI plus companion service; service lifecycle, clean upgrades and uninstall.
- Audit accessibility, localization and screen-reader flows; broad platform testing.
- Hardware-protected quarantine keys, authenticated signing-key rotation and provenance.

## Platform prevention

- Linux fanotify permission events with minimal privilege and carefully scoped policy; eBPF process events where appropriate.
- Windows ETW for reliable process telemetry, USN Journal recovery, and a signed audited minifilter for true on-access decisions.
- macOS Endpoint Security with approved entitlements, a reviewed system extension and secure broker boundaries.
- Memory scanning with per-platform permissions and explicit limitations.

## Future research

- Offline ML-lite models with published training/evaluation assumptions and false-positive controls.
- Archive scanning with nested-depth, expansion and timeout budgets; document/macro parsers in isolation.
- User-initiated hash-only cloud lookup with explicit endpoint consent, retention transparency and a local-only default.
- Optional browser extension for local malicious-download handoff, with the smallest possible permissions.
- Connection attribution and behavioral correlations without packet uploads or browsing-history collection.
- Opt-in local rule authoring tools, rule regression fixtures and signed community packs.

No roadmap item introduces premium tiers, telemetry, mandatory accounts, or upselling. Planned work is not advertised as current protection.
