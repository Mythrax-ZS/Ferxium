# Real-time monitoring and recovery

FerXium 0.1.3 improves after-change scanning. It does not prevent execution or inspect process memory. A healthy status describes the monitoring pipeline, not a guarantee that every file is safe.

## Event handling

Native inotify, ReadDirectoryChangesW and FSEvents notifications can be delayed or lost. The callback performs no file I/O or scanning. Its 4,096-entry channel uses nonblocking sends. Overflow, backend errors and `notify` rescan flags increment a separate atomic recovery generation: a full channel cannot discard the recovery request itself. Root deletion/rename also requests fresh registration.

The dispatcher drains events independently of scan workers and deduplicates at most 4,096 pending paths. Two foreground workers start new work as soon as a worker finishes. A 600 ms quiet interval coalesces writes; a five-second maximum postponement lets continuously modified files reach a scan attempt. This is a dispatch deadline, not a guaranteed verdict deadline. Older jobs eventually outrank executable/script priority. A path is never scanned by two foreground workers concurrently.

Transient sharing, permission and changing-file errors get three additional attempts with 250, 500 and 1,000 ms backoff. Persistent failures remain visible and request recovery. Excluded paths, application state, symlinks and special files are skipped. Maximum file sizes still limit coverage.

The scanner compares the opened file's size and modification time across the read, then verifies the current pathname refers to the same file identity. Windows uses volume/file IDs; Unix uses device/inode IDs. These are best-effort change checks, not an atomic snapshot or execution authorization. A malicious concurrent writer still needs stronger OS integration.

## Recovery and watch availability

One separately reserved worker streams configured watched folders through the existing safe traversal policy. It checks files present at startup, after missed-event signals, after directory creation/rename notifications and every 30 minutes. Moved-in folders are checked even without individual child notifications. Foreground scans continue during reconciliation.

Recovery records its starting generation. Signals received during the pass require another pass; completion never acknowledges later signals. Read/traversal failures preserve degraded coverage and retry after 30 seconds. New external signals can trigger an earlier pass. Unavailable roots retry registration with exponential backoff capped at 30 seconds. Accessible roots stay registered while another root is unavailable. Missing configured watch roots no longer prevent startup.

All recovery stays local and obeys exclusions/file limits. It cannot reconstruct historical process events, recover already-deleted files, decrypt archives or guarantee network filesystem coverage. Process polling remains every five seconds and can miss short-lived processes. Quick Scan checks existing process executables.

## Health and resource limits

The authenticated API adds `monitoring`: health, queue depth, active/maximum workers, oldest queued change, recovery activity/completions, retries, cumulative failures and the last unresolved error. The desktop shows active, recovering, degraded or inactive monitoring. Historical event-loss counters do not permanently degrade coverage after recovery. A backlog older than ten seconds does.

Monitoring starts at most three scan workers: two foreground workers and one reconciliation worker. One user/scheduled scan can run separately. Reads use the configured 1 KiB–256 MiB limit; native YARA keeps its three-second timeout. Worker count bounds simultaneous input buffers, not global CPU/memory usage. OS file I/O has no hard timeout; native parsers still share the service process. Sandboxed workers and OS execution gates remain future work.

Settings changes invalidate queued work and cooperative recovery. Shutdown waits for started monitoring work before saving state. Detections still require explicit review/actions; no automatic quarantine was added.

## Validation

- A deterministic 2,048-file burst fills a one-entry injected channel. A harmless matching file whose event is deliberately omitted must be found by reconciliation, with bounded workers/queues and eventual recovery checked.
- Scheduler tests cover continuous writes, priority without starvation, duplicate coalescing and retry backoff.
- Windows sharing-lock tests require detection after the writer releases the file.
- Native watcher tests check accessible roots continue when another root is unavailable.
- Packaged service smoke checks moved folders, degraded health after root disappearance, automatic registration after recreation and detection of a file present before registration.
- UI tests distinguish recovering/degraded monitoring and historical event loss. Existing tray and scan controls remain covered.

These use inert fixtures and validate pipeline behavior, not malware-corpus detection effectiveness.
