# Per-user startup templates

Install only after building and evaluating the service. These templates do not grant elevation, copy binaries, or install themselves. Keep executable paths outside monitored download folders and replace/re-sign them as part of a reviewed release process.

Linux: install `ferxium-service` into `~/.local/bin`, copy `ferxium.service` into `~/.config/systemd/user/`, then run `systemctl --user daemon-reload` and `systemctl --user enable --now ferxium`. Stop/unregister with `systemctl --user disable --now ferxium`.

macOS: replace the absolute executable placeholder in `org.ferxium.service.plist`, put it in `~/Library/LaunchAgents/`, and use `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.ferxium.service.plist`. Unregister using `launchctl bootout` with the same user domain/file. Test privacy authorizations for the actual executable you ship.

Windows: invoke `./packaging/Install-UserStartup.ps1 -ServiceBinary C:\ABSOLUTE\PATH\ferxium-service.exe` under your normal user. It registers a Limited, interactive-user logon task. Remove it with `Unregister-ScheduledTask -TaskName FerXium-UserProtection`; no credential is stored and no privileged Windows Service is created.

Tauri preview installers include the desktop, service, and CLI. Opening the installed desktop starts the service as your regular user. Startup registration is optional and uses the templates above; no privileged daemon is registered. Stop a running companion before updating or uninstalling the package. Coordinated updates and clean-machine installer audits remain production release work.
