# FerXium 0.1.0 preview builds

These packages include the desktop, current-user protection service, and CLI.
Opening the installed desktop starts the bundled service without administrator
privileges. Close an earlier service instance before replacing an installation.
Closing the desktop leaves monitoring active. The service does not run as root.

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
of the publisher. The bundled YARA rules and hash database are examples, not a
vetted production malware corpus. The project has not been independently audited.
Read the security model and dependency review before relying on these builds.
