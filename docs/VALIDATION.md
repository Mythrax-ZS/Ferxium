# Validation

Validated locally on Windows with Rust 1.98.1, Node.js 24.16.0, MSVC native tools and LLVM available. Standard CI checks pass on Windows, Linux, and macOS. The [native preview release workflow](https://github.com/Mythrax-ZS/Ferxium/actions/runs/37092906383) builds Windows x64 NSIS, Ubuntu 24.04 amd64 Debian, macOS Apple silicon DMG, and macOS Intel DMG packages.

- `cargo check` and the native Tauri desktop build.
- `cargo clippy --all-targets -- -D warnings` and Rust formatting.
- Default core/service tests, plus the YARA-enabled suite.
- Hash detection, heuristic combinations, exclusions, bounded sizes, and whitelist behavior.
- RenEngine coverage: four published IOC records, legacy MD5 lookup with SHA-256 identity/allowlisting, malformed/duplicate hash rejection, five ASCII and UTF-16 pattern matches, missing-signal negatives, and benign tool indicators. Inert embedded-rule fixtures do not match campaign or marker rules. These are synthetic tests, not a live-malware detection benchmark.
- Native Windows file watcher reports a harmless created file.
- Encrypted quarantine, changed-file rejection, ciphertext tamper detection, missing-key protection, and non-overwriting restore.
- Signed feed rejects forged keys, payload mutation, and replayed versions.
- Actual API route tests reject absent/wrong auth, browser Origin, oversized bodies, and invalid custom scan roots.
- Cooperative shutdown rejects wrong authentication and browser Origins. Restart-monitor tests check bounded crash backoff and exclusive ownership.
- Repeated scans count a known matching file each time while retaining one pending history report. The campaign service smoke requires the current scan's threat counter to be nonzero after watcher detection.
- Isolated daemon smoke: authenticated IPC → native watch → harmless YARA marker and RenEngine indicator fixture → quarantine → restore → delete backup → custom scan with campaign detection.
- TypeScript/Astro diagnostics and production builds for both frontends.
- Playwright: demo scan pause/resume/cancel and settings; phone navigation, honest downloads, FAQ; all six website pages.
- Desktop alert policy tests check report deduplication, reviewed findings, burst summaries, filename privacy and control-character filtering. Browser background preferences keep host startup and native test notifications unavailable.
- A fresh `npm ci` loads the local cache security backport through Astro; all 31 cache-reuse regression checks pass. `npm audit --audit-level=high` reports zero known vulnerabilities in its database checks. The local fork requires separate regression testing and review; see [backport provenance](../vendor/http-cache-semantics/BACKPORT.md).
- Cargo audit reports zero vulnerabilities and three informational warnings, including Linux glib unsoundness; see [the dependency review](DEPENDENCY_REVIEW.md). These warnings remain release follow-up work.

## Native packages

Version 0.1.4 adds a packaged supervisor smoke on all four release targets. It rejects a duplicate supervisor, checks direct child ownership before each of two deliberate worker crashes, requires rotated IPC tokens and resumed harmless YARA detection after each restart, then checks intentional shutdown does not restart. These tests use isolated private state and never print bearer tokens. Native graphical notification delivery and login behavior require OS integration checks; API acceptance cannot prove that the OS displayed a banner. See [background behavior and limits](BACKGROUND_PROTECTION.md).

Version 0.1.3 adds deterministic recovery after a 2,048-file burst with an intentionally undelivered matching-file event, worker/queue bounds, debounce deadlines, priority fairness, Windows sharing-lock retries, file-identity replacement checks and partial-root availability. Packaged service smoke also verifies moved-in folders, degraded health while a root is missing and automatic recovery after recreation. See [monitoring validation and limits](REALTIME.md).

- Windows: extracted the release NSIS payload and confirmed the desktop, service, and CLI executables are present. Ran the packaged service smoke test as a regular user.
- Windows desktop 0.1.3: launched an isolated copy without the companion service, delivered native window-close and tray-click notifications, and verified the window hides while its process and tray survive. Verified tray reopening and restoration from a minimized state, then invoked the actual native tray Quit menu and checked a clean exit. macOS Dock reopening is compiled and checked by native macOS builds; it has not been exercised interactively from this workspace.
- Windows desktop 0.1.4: launched with isolated state and its own YARA-enabled companion, verified background startup leaves the window hidden, created an inert marker and observed the native notification dispatch ledger while hidden, and checked repeated polling does not duplicate dispatch. A second manual launch exited cleanly and reopened the original window. Close/reopen, minimized restoration and actual tray Quit passed. This validates native dispatch, not OS banner delivery; login registration, real sign-in and graphical macOS/Linux notifications still need installed-system integration testing.
- Linux: extracted the release Debian package into an isolated Ubuntu 24.04 environment. Checked its declared GTK/WebKit/AppIndicator/OpenSSL runtime dependencies and service library resolution, ran the CLI, and passed the packaged service smoke test as a regular user.
- macOS: release CI mounts each DMG, verifies the app's ad-hoc code signature, checks service library linkage, runs the bundled CLI, and executes the packaged service smoke test on the native runner.

Version 0.1.2 release CI also runs the YARA-enabled regression suite and requires the release CLI to scan the actual desktop, service, and CLI binaries as clean on every platform. This guards against self-detection from embedded rule text. The gate exposed release optimization embedding the EICAR test string; the matcher now compares encoded bytes without constructing that string. Its positive and near-miss regression runs in memory because host antivirus can intercept EICAR files before FerXium reads them.

Intel macOS watcher checks timed out in 0.1.1 and the first 0.1.2 candidates. Diagnostics showed an active watcher without the expected file event. Source review found that watch registration used aliases such as `/var` while the native watcher regression used canonical paths. Version 0.1.2 resolves watch roots before registration and tests a symlink in the parent path. This addresses a documented FSEvents path requirement; it does not prove that every earlier timeout had the same cause. The smoke deadline remains 20 seconds, with bounded diagnostics and no IPC token output. Additional startup and load testing remains follow-up work.

The smoke test exercises authenticated IPC, the native file watcher, harmless YARA detection, quarantine, restore, deletion, and a custom scan. Package hashes are checked before importing download metadata, checked again on the VPS before deployment, and checked against public HTTPS downloads after deployment. No preview has a publisher certificate; macOS ad-hoc integrity signatures do not establish publisher identity or notarization. Clean-machine graphical installer and desktop integration testing remain release milestones.

Intel diagnostics after the watch-path fix showed the first marker detected, then a second fixture delayed while hundreds of executables were scanned during startup. Process monitoring now establishes a baseline instead of enqueueing already-running executables. Quick Scan retains coverage of existing process files; the native smoke deadline remains unchanged.

## Reproduce checks

Reproduce the service flow after building with native YARA:

```sh
cargo build -p ferxium-service --features yara-engine
node scripts/service-smoke.mjs
```

The script starts a hidden current-user service using `--data-dir` in a temporary directory, scans only harmless marker content, then stops its child. It retains isolated state for inspection and prints that directory. It never installs startup tasks or modifies normal application state.

Reproduce browser checks:

```sh
npx playwright install chromium
npm run test:ui
```

Screenshots appear in ignored `artifacts/desktop.png` and `artifacts/website.png`. The browser UI is an illustrative demo, so these checks do not establish native webview interoperability, OS protection efficacy, detection quality, certification, or an independent audit.
