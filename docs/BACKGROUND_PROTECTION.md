# Background protection and notifications

Version 0.1.4 adds native threat notifications, optional login startup and a
separate current-user restart monitor. These complement [after-change
scanning](REALTIME.md); they do not block execution or automatically quarantine
files.

## Alerts

The installed desktop polls authenticated service status from Rust, independently
of the webview. Closing its window hides it to the tray and keeps alerts active.
New pending findings request an operating-system notification. Repeated scans of
the same pending report do not repeat the alert. IDs are saved privately across
desktop restarts; a burst produces one summary. Existing pending findings on
first launch can produce a summary too.

Notifications contain a sanitized, length-limited filename and detection name,
or a finding count. Full paths and file contents are omitted. Findings still
require review in FerXium; an alert does not mean a file has been contained.
Settings provides **Threat notifications** and **Send test notification**.
Disabling alerts acknowledges findings observed while disabled, so reenabling
does not replay that backlog. A notification-history write failure is shown in
Settings; a later desktop restart can repeat an alert if its ID was not saved.

The OS may suppress banners under Focus/Do Not Disturb, deny notifications, or
retain them only in its notification center. The notification backend can accept
a request before delivery; FerXium cannot prove a banner was displayed. On
Windows, use an installed release for application identity; development runs
can appear under PowerShell. See [Tauri's native notification
documentation](https://v2.tauri.app/plugin/notification/).

**Quit desktop (service stays active)** stops notifications because their owner
is the desktop process. Scanning and worker recovery continue. Keep the desktop
in the tray for alerts.

## Sign-in startup

Enable **Start at login** in an installed release's Settings. This registers the
current desktop executable for your account, with the fixed `--background`
argument. It starts hidden, creates the tray, starts the restart monitor and
requests alerts. A second manual launch reopens the existing window. Startup is
off until explicitly enabled and needs no administrator rights. It starts after
sign-in, not before sign-in or before other programs can execute.

The setting is unavailable for debug builds and isolated `--data-dir` sessions.
Disable it before uninstalling or moving the app. Manual service startup
templates remain alternatives for headless operation; they do not start the
desktop notification owner. Avoid registering both mechanisms.

## Worker recovery and stopping

The desktop launches its bundled service with `--supervise`. That process holds
`supervisor.lock` and launches only its own executable as the scanning worker.
The worker owns `service.lock`. Duplicate supervisors exit; an existing
standalone worker is allowed to finish instead of being terminated.

An abnormal worker exit schedules a restart after 1, 2, 4, 8, 16, then at most
30 seconds. A worker surviving 60 seconds resets the consecutive failure delay.
Each restart rotates the IPC bearer token and port; the desktop reads discovery
again and clears cached healthy status on connection failures. Saved scan
history, quarantine and settings survive. Monitoring reconciles watched folders
at startup. A deliberately paused protection setting remains paused.

The private heartbeat exposes state and restart count in Settings. A missing or
stale heartbeat is displayed as unavailable. Temporary heartbeat-write errors
do not stop supervision. The watchdog detects process exits, not hung scanners;
crash recovery does not provide tamper resistance or restart a killed watchdog.

To stop both processes before upgrading or repairing state, use the installed
service executable:

```sh
ferxium-service --stop
```

For isolated state, append `--data-dir /absolute/path`. The stop request identifies
the active supervisor by a random generation ID. Worker shutdown uses the
authenticated, Origin-rejecting local API. The supervisor allows its own child
ten seconds to stop, then terminates that owned child if necessary. It never
kills a process based on a PID from discovery. A clean worker exit ends
supervision and is not restarted. A foreground `ferxium-service` still supports
Ctrl+C and does not gain a watchdog unless `--supervise` is supplied.

Close the desktop before stopping for maintenance; reopening it intentionally
starts protection again. If startup repeatedly fails, stop the supervisor and
run the service in the foreground to inspect diagnostics. Back up complete
private state before repairs, particularly the quarantine encryption key.

## Validation

`scripts/supervisor-smoke.mjs` starts isolated supervised state, rejects a
duplicate supervisor, verifies direct parent ownership before crashing its
worker twice, checks credential rotation and resumed inert-marker detection,
then verifies intentional stopping does not restart it. Build with native YARA:

```sh
cargo build --locked -p ferxium-service --features yara-engine
node scripts/supervisor-smoke.mjs
```

Native CI runs this against each platform's service, including the service
inside both macOS DMGs. Desktop Rust tests cover report deduplication, reviewed
findings, burst summaries and filename privacy. Browser tests ensure preview
controls cannot configure host startup or send native notifications. These
checks do not establish malware detection efficacy or guarantee OS delivery.
