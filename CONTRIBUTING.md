# Contributing

Start with a focused issue or patch describing the behavior you want to improve. Include platform, reproduction steps, expected/observed results, and the relevant source-preview coverage limits.

Use harmless deterministic fixtures. Never execute submitted samples, attach live malware to public issues, or expand telemetry, cloud upload, or privileges without a separately reviewed design. Heuristics must explain their evidence and false-positive risk. Automatic destructive responses are deliberately absent.

Keep the core independent of UI and transport. Validate untrusted files, feed payloads, paths, and action parameters at the boundary. Use safe Rust where possible. Document every unsafe block's assumptions and cleanup. Preserve bounded reads/queues, visible failures, and non-overwriting restores.

Run the README checks. Add meaningful regression coverage for detection, auth, persistence, containment, or privilege boundaries. UI changes should be checked at narrow widths, by keyboard, and with reduced-motion preferences. Avoid tests that merely mirror style or component markup.

Pull requests should state the concrete problem, resulting behavior, validation, and any coverage changes. Follow the MIT license. Maintainers should configure private vulnerability reporting before enabling public issue intake.
