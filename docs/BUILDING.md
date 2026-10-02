# Building FerXium

Use stable Rust, Node.js 22.12+ and npm. The Rust workspace defaults to core/service/CLI so headless Linux builds do not need WebKit. Commit and use both lockfiles. All commands run at the repository root unless stated otherwise.

## Windows

Install Visual Studio 2022 Build Tools with Desktop development with C++, a Windows SDK, and WebView2. Use the MSVC Rust target. Native YARA's vendored C sources require a working C compiler; LLVM/libclang is needed if a dependency regenerates bindings.

```powershell
npm ci
cargo build --release -p ferxium-service -p ferxium-cli
npm run tauri -- build
```

The service executable is `target/release/ferxium-service.exe`. The GUI executable is `target/release/ferxium-desktop.exe`; Tauri bundles appear under `target/release/bundle/`. Native bundles include the service and CLI; the installed UI starts its bundled current-user service. Development builds can still run the service separately. This preview does not register a privileged Windows Service.

## Linux (Debian/Ubuntu)

```sh
sudo apt-get update
sudo apt-get install build-essential pkg-config libwebkit2gtk-4.1-dev \
  libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev clang
npm ci
cargo build --release -p ferxium-service -p ferxium-cli
npm run tauri -- build
```

Other distributions need equivalent WebKitGTK 4.1, GTK 3, AppIndicator, SVG, SSL, and compiler development packages. For headless builds, omit desktop dependencies. Watch roots must be readable, and inotify limits may constrain large trees.

## macOS

```sh
xcode-select --install
npm ci
cargo build --release -p ferxium-service -p ferxium-cli
npm run tauri -- build
```

Build on each intended architecture, or configure universal targets and dependencies explicitly. Protected folders may require macOS privacy authorization; Full Disk Access should be a deliberate user choice.

## Development and preview

```sh
cargo run -p ferxium-service
# Separate terminal:
npm run tauri -- dev
# Browser-only UI demo:
npm run dev:desktop
# Static website:
npm run dev:website
```

Browser mode is illustrative and has no host filesystem permissions. Native mode shows the service as offline when it cannot connect; it does not fall back to a simulated protected state.

## YARA

```sh
cargo build -p ferxium-service --features yara-engine
cargo test -p ferxium-core --features yara-engine
```

The `yara` crate compiles vendored native YARA. Hash and heuristic scanning remain available without this feature. Native scanning has a three-second YARA timeout per file. Signed updates presently update hashes, not YARA source; review and rebuild trusted rules with the application.

## Rebuild icons

```sh
npm run tauri -- icon public/shield.svg --output src-tauri/icons
```

Generated desktop icons are included. The source is an original code-native SVG. Website fonts are bundled locally; no external font requests are needed.

References: [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/), [native dialogs](https://v2.tauri.app/plugin/dialog/), [Astro styling](https://docs.astro.build/en/guides/styling/).
