# Architecture decisions

The core crate is transport/UI independent. Its modules separate regular-file reading, detections, configuration, native watching, encrypted storage, and authenticated updates. Scanner instances are immutable and shared; long scans use an engine/config snapshot so updates cannot change verdicts mid-job.

The service owns state, scheduled work, monitoring, quarantine, and one active manual/scheduled job. API actions serialize through an async mutex; expensive file operations use blocking workers. Status snapshots avoid vault/state lock inversions. The scanner streams two filesystem passes: count accessible candidate files, then scan. Counts and ETA are estimates if the filesystem changes between passes. Enumeration has no invented percentage. Pause/cancel is cooperative between file scans; in-progress native matching can take up to its timeout.

Real-time paths enter a 4096-event channel, then a capped debounce map. Two foreground workers scan independently of event collection; completion immediately makes capacity available. A reserved reconciliation worker checks watched folders after event loss, startup, directory moves and periodic sweeps. Separate atomic generations retain recovery requests even when the event channel is full. Transient file-read errors retry with backoff. Watch registration retains accessible roots while unavailable roots retry; incomplete coverage appears as degraded health. See [monitoring details](REALTIME.md). Later adapters can implement `ExecutionMonitor`; current monitoring does not block execution.

Processes are sampled by PID/start-time identity and newly observed executable paths enter the same queue. Network snapshots remain local metadata. No threat score or blocking decision is invented from an ordinary network connection.

The Tauri process is an authenticated client. It reads discovery privately, keeps the token in Rust, and exposes structured status/actions to its local window. Browser builds use explicit demo data; native failures always show offline status. Native dialogs select folders and restore destinations. Tray actions use the same service API and surface errors to the UI.

A native desktop poller maintains cached status and requests deduplicated OS notifications independently of webview timers. Login startup is an explicit current-user setting with fixed background arguments. The desktop starts a separate service supervisor; bounded crash backoff, rotated IPC discovery and owned child handles keep worker recovery outside UI lifetime. Clean worker shutdown is not restarted. See [background protection](BACKGROUND_PROTECTION.md) for operational limits and stop commands.

The Astro website is independent static output. It bundles fonts, icons, theme/menu scripts, and content locally. No remote analytics, images, font CDNs, badges, or sample uploads are embedded. Release assets are build-time validated data. The static product preview and quotes are explicitly illustrative.

Tradeoffs deliberately documented for the preview: same-user loopback IPC rather than a privileged broker, JSON retention rather than a journaled database, polled process awareness rather than guaranteed process events, optional YARA native code rather than mandatory C tooling, and source builds rather than fabricated installer links.
