# Dependency review for the source preview

Local npm audit reports no known vulnerabilities in the committed npm dependency graph. Cargo audit reports zero entries in its vulnerability list and **three informational warnings**; a successful exit is not an all-clear for production deployment.

| Package                | Advisory                                            | Scope and required follow-up                                                                                                                                                                                                                                                     |
| ---------------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| glib 0.18.5            | RUSTSEC-2024-0429, unsound iterator implementations | Linux desktop GTK/WebKit dependency chain. The affected `VariantStrIter` methods are fixed in glib 0.20+, but the GTK 3 stack used by Tauri binds to 0.18. Resolve through a reviewed compatible backport or upstream desktop-stack update before claiming production readiness. |
| paste 1.0.15           | RUSTSEC-2024-0436, unmaintained                     | Transitive Linux network socket dependencies. Track upstream replacement and assess the maintenance risk.                                                                                                                                                                        |
| proc-macro-error 1.0.4 | RUSTSEC-2024-0370, unmaintained                     | Transitive Linux desktop macro dependencies. Track upstream replacements.                                                                                                                                                                                                        |

The application does not directly invoke the affected glib iterator methods. That fact alone does not prove transitive code is unaffected. The repository does not suppress these warnings or present the audit as an independent code review. Native YARA and system WebView/GTK dependencies also require separate security maintenance and runtime testing.

Reproduce with `cargo install cargo-audit --locked`, then `cargo audit`. Check all targets rather than filtering to the host OS. Review lockfile changes and keep the warning log visible in CI.

Sources: [glib unsoundness advisory](https://rustsec.org/advisories/RUSTSEC-2024-0429.html), [paste maintenance advisory](https://rustsec.org/advisories/RUSTSEC-2024-0436.html), [proc-macro-error maintenance advisory](https://rustsec.org/advisories/RUSTSEC-2024-0370.html).
