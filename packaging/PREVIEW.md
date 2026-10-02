# FerXium 0.1.2 preview builds

Adds four valid published legacy MD5 indicators and five original YARA patterns
for the RenEngine / RenPy Loader chain described by Malwarebytes on July 20, 2026.
Coverage is local and static; encrypted archives and process memory remain outside
current scanning. See [coverage notes](https://github.com/Mythrax-ZS/Ferxium/blob/main/docs/THREAT_COVERAGE.md).
Rules are tested with inert indicators, not live malware. The malformed final
payload hash in the report is excluded. Ordinary development tools alone are not
flagged by these campaign rules. No network blocking is added.
Repeated scans also count matching files already present in pending history.
Watch roots resolve filesystem aliases before native registration, including
macOS temporary folders under `/var`.

These packages include the desktop, current-user protection service, and CLI.
Opening the installed desktop starts the bundled service without administrator
privileges. Close an earlier service instance before replacing an installation.
Closing the window hides FerXium to the tray while monitoring stays active.
Click its tray icon or choose Open FerXium to reopen it. Quit desktop from the
tray menu exits the UI explicitly and leaves the protection service active.
The service does not run as root.

Windows: install the x64 setup as your regular user. WebView2 is required; the
installer handles its runtime prerequisite. This preview has no Authenticode
publisher signature.

Linux: the amd64 Debian package targets Ubuntu 24.04 or newer with GTK 3,
WebKitGTK 4.1, and AppIndicator. Install using your distribution package manager
and launch FerXium from the application menu. Installation needs package-manager
privileges; running the app and service uses your normal user.

macOS: select Apple silicon (aarch64) or Intel (x86_64), open the DMG and copy
FerXium.app to Applications. macOS 11 or newer is required. Builds use local ad-hoc
signatures for executable integrity; they have no Developer ID signature or Apple
notarization and may be blocked by Gatekeeper. This is an evaluation release.

Each download has a SHA-256 checksum. A checksum verifies bytes, not the identity
of the publisher. The bundled rules include tests and targeted indicators, not a
vetted production malware corpus. The project has not been independently audited.
Read the security model and dependency review before relying on these builds.
