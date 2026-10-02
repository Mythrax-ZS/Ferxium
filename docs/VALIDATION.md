# Local validation

Validated on Windows with Rust 1.98.1, Node.js 24.16.0, MSVC native tools and LLVM available. Linux/macOS jobs are configured in GitHub Actions; those remote jobs have not been run from this workspace.

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
