# Releasing responsibly

## Before public antivirus positioning

Complete independent security review, realistic false-positive and detection testing, filesystem-race and crash-recovery hardening, resource-exhaustion testing, platform permission review, signed installer validation, and a maintainable vetted malware corpus. Source previews must retain accurate coverage labels. Do not claim a kernel execution gate until one is implemented and validated.

Resolve or independently assess the platform dependency warnings in [DEPENDENCY_REVIEW.md](DEPENDENCY_REVIEW.md), including the Linux desktop glib iterator unsoundness advisory. A passing cargo audit exit code includes informational warnings; do not describe it as an audit finding no issues.

Configure a real GitHub repository, enable private vulnerability reporting, set `SITE_URL`/`PUBLIC_REPOSITORY_URL`, and replace template destinations. CI produces build artifacts for evaluation; it does not publish an audited signed release or install a service automatically.

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

After signing and verifying installers, add their exact HTTPS URLs and computed SHA-256 values to `apps/website/src/data/releases.json`:

```json
{
  "version": "0.1.0",
  "status": "source-preview",
  "assets": [
    {
      "platform": "windows",
      "architecture": "x86_64",
      "name": "ACTUAL-PUBLISHED-ASSET.exe",
      "url": "https://YOUR-REAL-RELEASE-HOST/ACTUAL-PUBLISHED-ASSET.exe",
      "sha256": "REPLACE_WITH_THE_ACTUAL_64_CHARACTER_SHA256"
    }
  ]
}
```

The example checksum is intentionally invalid and must not be copied into a release. Website builds reject malformed checksums/URLs. Keep the release status and marketing coverage aligned. Replace testimonial placeholders only with permission and authentic attribution. Stars/download counters remain placeholders unless sourced truthfully without tracking users.
