# RenEngine / RenPy Loader campaign coverage

FerXium 0.1.2 adds local file detection derived from [Malwarebytes' July 20, 2026 analysis](https://www.malwarebytes.com/blog/threat-intel/2026/07/fake-games-spread-stealers-with-renpy-loader-msbuild-and-etherhiding). This is targeted preview coverage, not comprehensive Amatera detection or an independent live-sample benchmark.

## What is checked

- Four valid published MD5 file indicators identify the reported Nancy, GollopDevest, and anti-analysis DLLs. They are in `signatures/hashes.json`, database version 2.
- Five original YARA rules check combinations associated with the config loader, headless MSBuild launcher, reflective project loader, trojanized Nancy resources, and EtherHiding downloader. See `signatures/renengine-2026-07.yar`.
- Each pattern requires multiple distinctive strings. The two DLL rules also require DOS and PE headers. Ren'Py, Nancy, MSBuild, public blockchain providers, filenames, and `eth_call` alone do not trigger these rules.

The rules run in quick, full, custom, scheduled, and watched-file scans through the same engine. Native preview packages enable YARA. Default Rust builds without `yara-engine` retain the four hash lookups but do not run these five patterns. Toggleable generic heuristics are separate from signatures; disabling heuristics does not disable YARA or exact IOC matching. Exclusions, SHA-256 allowlisting, file limits, and access permissions still apply.

## Integrity and source caveats

MD5 is a legacy IOC identifier, not a security integrity primitive. Reports, allowlisting, quarantine verification, and installer checksums continue to use SHA-256; feed authenticity uses Ed25519. MD5 cannot establish publisher trust and deliberate collisions can undermine identification.

The optional `md5_signatures` array is validated for lowercase 32-digit hexadecimal hashes, duplicate entries, bounded descriptions, and a combined 20,000-entry database limit. Existing SHA-256-only databases still parse. Older clients reject the new field; upgrade the app before using a version-2 feed. YARA updates require a reviewed application rebuild.

The final payload hash printed in the source, `F8453EFE408CE25B9484F872797E3D63`, has 31 digits. It is excluded rather than padded or guessed. The source also spells the anti-analysis DLL both PavinWide and PavinWride; its valid hash is preserved. No malware samples were downloaded or executed to develop this coverage.

## Limits and validation

These are static byte rules. They do not decompress RPA/ZIP archives, decrypt payloads, inspect process memory, block execution, resolve blockchain C2, or block network destinations. Changed hashes, encrypted strings, altered keys, and different packaging can evade them. Scanning a visible extracted component improves coverage; no instruction here requires running a suspicious installer.

Harmless tests exercise MD5 lookup, SHA-256 identity/allowlisting, malformed IOC rejection, five ASCII and UTF-16 patterns, missing-indicator negative cases, and ordinary tool indicators. The service smoke test verifies a non-executable campaign fixture through the native watcher and authenticated API. These tests validate implementation behavior, not effectiveness against a real malware corpus.

```sh
cargo test --locked -p ferxium-core
cargo test --locked -p ferxium-core --features yara-engine
cargo build --locked -p ferxium-service --features yara-engine
node scripts/service-smoke.mjs
```
