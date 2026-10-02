# Releasing responsibly

## Before public antivirus positioning

Complete independent security review, realistic false-positive and detection testing, filesystem-race and crash-recovery hardening, resource-exhaustion testing, platform permission review, signed installer validation, and a maintainable vetted malware corpus. Source previews must retain accurate coverage labels. Do not claim a kernel execution gate until one is implemented and validated.

Resolve or independently assess the platform dependency warnings in [DEPENDENCY_REVIEW.md](DEPENDENCY_REVIEW.md), including the Linux desktop glib iterator unsoundness advisory. A passing cargo audit exit code includes informational warnings; do not describe it as an audit finding no issues.

The repository is https://github.com/Mythrax-ZS/Ferxium. Enable private vulnerability reporting and set `SITE_URL`/`PUBLIC_REPOSITORY_URL` when building the website. Native release CI publishes evaluation packages on version tags; it does not establish an audited or publisher-signed release. Packages include a service started as the current user by the desktop, without automatic OS startup registration.

## Build and sign

Build GUI, service, and CLI from the same commit with committed lockfiles. The native build command compiles the YARA-enabled service and CLI and bundles both as sidecars. The installed desktop starts its sibling service as the current user; the service's state lock rejects duplicate instances. No automatic OS startup registration is shipped. Close a running companion before updating or uninstalling the package. Platform publisher signing and clean-machine installer tests remain release milestones.

Windows: sign the GUI, service, CLI, and installer with Authenticode using a maintained certificate/signing provider. Configure Tauri's Windows signing settings in a release-specific configuration; never commit certificate passwords. Timestamp signatures and validate them using the platform verifier. Test on a clean non-admin Windows installation with WebView2.

macOS: use Developer ID Application signing, hardened runtime, appropriate entitlements, and notarization. Sign every shipped executable, submit the package through `notarytool`, and staple the accepted ticket. Test both architectures and protected-folder permissions. An Endpoint Security client requires separate Apple entitlements and is not present in this preview.

Linux: build distribution-appropriate packages, publish authenticated checksums and provenance, and test desktop/tray compatibility plus per-user systemd behavior. Do not request root merely to run the scanning daemon.

References: [Tauri Windows signing](https://v2.tauri.app/distribute/sign/windows/), [Tauri macOS signing](https://v2.tauri.app/distribute/sign/macos/), [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

## Hash-feed signing

The signed envelope format is `{ "payload": "EXACT UTF-8 database text", "signature": "Ed25519 signature hex" }`. The public key is configured explicitly by the user. The payload uses the same schema as `signatures/hashes.json` and increases its version on every publication.

```sh
# Run on an isolated signing system. Dependencies are Python's cryptography package.
python scripts/sign-feed.py keygen --private /secure/ferxium-feed-key.pem
python scripts/sign-feed.py sign --private /secure/ferxium-feed-key.pem \
  --database signatures/hashes.json --output signatures.signed.json
```

The keygen command prints the public key only; it creates the private file exclusively. Store the private key offline and publish only the envelope through HTTPS, including GitHub raw hosting if desired. Configure its HTTPS URL and public key in Settings, save, then check updates. Serve no redirects. An unchanged or older version is rejected. Signature updates do not deliver YARA source or app binaries.

For key rotation, stop the service, preserve an authenticated backup of the old envelope/config, verify the new feed/key out of band, remove the old cache deliberately, and configure the new key before restarting. Do not silently replace a pinned key. Hardware signing and authenticated delegated rotation are future work.

## Website release assets

Push a new `v*` tag to run `.github/workflows/release.yml`. It builds Windows x64 NSIS, Ubuntu 24.04 amd64 Debian, macOS Apple silicon DMG, and macOS Intel DMG packages on native runners. macOS packages receive ad-hoc integrity signatures and are checked from the mounted DMG, including a packaged service smoke test. All four jobs must pass before CI creates a GitHub prerelease with packages, checksum files, and platform metadata. Publisher signing remains a separate release milestone.

Download each `release-*` artifact into one local folder, then run `python scripts/import-release.py DIRECTORY`. The script verifies the bytes against every metadata checksum before updating `apps/website/src/data/releases.json`. Build the site, copy those exact packages and checksum files into `apps/website/dist/downloads`, and deploy according to [DEPLOYMENT.md](DEPLOYMENT.md). Never substitute a separately rebuilt package for the one named in the manifest.

The manifest records the exact HTTPS URL, signature status, package kind, and computed SHA-256 value for each asset:

```json
{
  "version": "0.1.1",
  "status": "preview",
  "assets": [
    {
      "platform": "windows",
      "architecture": "x86_64",
      "name": "ACTUAL-PUBLISHED-ASSET.exe",
      "url": "https://YOUR-REAL-RELEASE-HOST/ACTUAL-PUBLISHED-ASSET.exe",
      "sha256": "REPLACE_WITH_THE_ACTUAL_64_CHARACTER_SHA256",
      "signed": false,
      "kind": "installer"
    }
  ]
}
```

The example checksum is intentionally invalid and must not be copied into a release. Website builds reject malformed checksums/URLs. Keep the release status and marketing coverage aligned. Replace testimonial placeholders only with permission and authentic attribution. Stars/download counters remain placeholders unless sourced truthfully without tracking users.
