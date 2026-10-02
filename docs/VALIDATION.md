# Validation

Validated locally on Windows with Rust 1.98.1, Node.js 24.16.0, MSVC native tools and LLVM available. Standard CI checks pass on Windows, Linux, and macOS. The [native preview release workflow](https://github.com/Mythrax-ZS/Ferxium/actions/runs/36982311382) builds Windows x64 NSIS, Ubuntu 24.04 amd64 Debian, macOS Apple silicon DMG, and macOS Intel DMG packages.

- `cargo check` and the native Tauri desktop build.
- `cargo clippy --all-targets -- -D warnings` and Rust formatting.
- Default core/service tests, plus the YARA-enabled suite.
- Hash detection, heuristic combinations, exclusions, bounded sizes, and whitelist behavior.
- Native Windows file watcher reports a harmless created file.
- Encrypted quarantine, changed-file rejection, ciphertext tamper detection, missing-key protection, and non-overwriting restore.
- Signed feed rejects forged keys, payload mutation, and replayed versions.
- Actual API route tests reject absent/wrong auth, browser Origin, oversized bodies, and invalid custom scan roots.
- Isolated daemon smoke: authenticated IPC → native watch → harmless YARA marker → quarantine → restore → delete backup → custom scan.
- TypeScript/Astro diagnostics and production builds for both frontends.
- Playwright: demo scan pause/resume/cancel and settings; phone navigation, honest downloads, FAQ; all six website pages.
- npm audit reports zero known vulnerabilities after dependency refresh.
- Cargo audit reports zero vulnerabilities and three informational warnings, including Linux glib unsoundness; see [the dependency review](DEPENDENCY_REVIEW.md). These warnings remain release follow-up work.

## Native packages

- Windows: extracted the release NSIS payload and confirmed the desktop, service, and CLI executables are present. Ran the packaged service smoke test as a regular user.
- Linux: extracted the release Debian package into an isolated Ubuntu 24.04 environment. Checked its declared GTK/WebKit/AppIndicator/OpenSSL runtime dependencies and service library resolution, ran the CLI, and passed the packaged service smoke test as a regular user.
- macOS: release CI mounts each DMG, verifies the app's ad-hoc code signature, checks service library linkage, runs the bundled CLI, and executes the packaged service smoke test on the native runner.

The smoke test exercises authenticated IPC, the native file watcher, harmless YARA detection, quarantine, restore, deletion, and a custom scan. Package hashes are checked before importing download metadata, checked again on the VPS before deployment, and checked against public HTTPS downloads after deployment. No preview has a publisher certificate; macOS ad-hoc integrity signatures do not establish publisher identity or notarization. Clean-machine graphical installer and desktop integration testing remain release milestones.

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
