# Security model and operational boundaries

## Scope

The service is a **current-user** application. It cannot protect its state from an attacker who already executes code as that user or as an administrator. It must not become a root/admin broker for lower-trust desktop clients. Windows and Unix startup refuse elevation. Kernel prevention and tamper resistance need a separate design, authenticated OS IPC, constrained handles, and independent review.

The engine reads untrusted bytes but never executes them. Regular-file checks, no-follow flags, a maximum input size, native YARA timeouts, streaming walkers, bounded event queues, and limited retained reports constrain common resource attacks. Native YARA remains an additional C dependency and should eventually be isolated in a restricted worker. The service currently has one background scan plus serialized real-time file workers.

## IPC

Only IPv4 loopback is bound. Each service instance rotates a 256-bit bearer token; a private discovery file communicates the ephemeral port to same-user Rust clients. Unix storage uses mode 0700/0600. Windows sets a protected ACL allowing the current SID and SYSTEM before writing secrets. A lock prevents multiple services from sharing the state.

Every API route requires a bearer token. Browser `Origin` headers are rejected, there is no CORS support, no cookie or query-string auth, and JSON request bodies are limited to 64 KiB. Tauri's local main window receives only two allowlisted commands and native dialog permissions. Rust validates structured actions; the token never reaches frontend JavaScript. The webview has a restrictive CSP, no remote content, no shell plugin, and no general file API.

This is a local same-user transport, not mutual service identity authentication. A same-user program can read discovery, impersonate the daemon, or alter config. Moving to a privileged service requires OS-backed peer identity and a different authorization design; a loopback bearer token is insufficient for that boundary.

## Detection and visibility

Native watchers observe filesystem events after they happen. They do not deny open/execute access. Process polling every five seconds can miss short-lived processes; only executable files are scanned, not memory. Network summaries are sampled local socket/interface metadata, not traffic inspection or prevention. A watcher error or full queue increments a visible dropped-event counter; there is no guaranteed replay/reconciliation yet.

Scans use the initiating configuration and engine snapshot. Changing settings or signatures affects later jobs. Full traversal omits state, staging directories, symlinks, special files and Linux pseudo filesystems. Exclusions and maximum file size reduce coverage. A heuristic finding is a review signal, not a malware verdict. Bundled hashes/rules are illustrative. No claim is made of comprehensive malware detection or independent certification.

## Quarantine

Only explicit threat IDs can trigger quarantine; there is no arbitrary path-delete API. A changed source hash is rejected. Content is encrypted using ChaCha20-Poly1305 with a random nonce and authenticated ID/hash. A per-user local key is not hardware-protected and must be backed up securely if recovery is needed.

An encrypted backup and metadata are committed before moving the original into a private `.ferxium-hold-ID` directory beside the source. The moved file is rehashed before deleting it. A mismatch attempts a non-overwriting hard-link recovery; if another object occupies the original path, the staged file is retained and its path remains in metadata. This is defense in depth for a user-scoped application, not an atomic privileged containment primitive or a defense against hostile same-user path races.

Failures can leave an encrypted backup, a private staged plaintext file, or an unchanged original. The UI marks these actions incomplete. Crashes between source removal and the final metadata write can leave a conservative incomplete status. Resolve staging before restore/deleting the backup. A fully contained record requires `source_removed: true` and no staging path. Pending detections are never automatically deleted.

Restore authenticates ciphertext and SHA-256, checks the destination parent, refuses application state, and uses `create_new` so existing files are never overwritten. Unix restores use 0600 and do not reinstate executable bits or original ACLs. Metadata preservation is future work. Backups remain until explicitly removed; deleting them is not guaranteed secure erasure on modern storage.

## Recovery

FerXium reuses an existing AegisGuard preview state directory in place, preserving quarantine ciphertexts and their encryption key. New installations use the FerXium directory. If both directories exist, default startup fails instead of silently selecting a vault. Stop all instances and back up both complete directories before manually reconciling them; never overwrite or discard either key. The service's `--data-dir` override is for isolated development or recovery, and the default desktop/CLI discovery does not follow that override. Disable any earlier startup task before installing the renamed one.

Stop the service before manually repairing state. Back up the entire private state folder, including `quarantine/key.bin`, metadata, and ciphertexts. Do not create a replacement key for old ciphertext. Read the entry's `staging_path`, verify that file exists, and restore it to a new safe location without overwriting files. Treat retained plaintext as untrusted. Preserve evidence if source/backup hashes differ. Clear or amend interrupted metadata only after recovering and verifying the data.

Local state is JSON, atomically replaced on the same filesystem. Corrupt state fails startup rather than silently discarding detections. A storage failure is reported. Persisted history retains 100 scans and 500 detections, activity retains the latest 100 session events, and quarantine limits entries to 1024 with a 2 GiB ciphertext quota. JSON state is capped at 5 MiB per file. These are retention bounds, not a production database strategy. A journaled database with crash recovery and comprehensive disk quotas belongs in the next milestone.

## Updates and privacy

No outbound request happens for scanning. No cloud provider is configured. Opt-in updates use HTTPS, reject redirects, cap response size, verify exact payload bytes under a pinned Ed25519 key, reject future publication timestamps, and require a strictly increasing version. Cached updates are verified on startup. The current rollback defense protects normal updates; deleting/replacing local state as the same user is outside the threat boundary.

The update host sees an IP address and request metadata. It receives no scan paths, file hashes, contents, reports, or process lists. Signing keys belong offline or in a signing service, never in this repository. Trusted-key rotation requires an explicit cache migration. Rules are not remotely updated in this release.

References: [Tauri capability model](https://v2.tauri.app/security/capabilities/), [YARA C scanning semantics](https://github.com/VirusTotal/yara/blob/master/docs/capi.rst), [notify backend limitations](https://docs.rs/notify/latest/notify/).
