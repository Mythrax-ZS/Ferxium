# FerXium cache security backport

This is a local, BSD-2-Clause-licensed fork of `http-cache-semantics` **4.2.0**.
`4.2.1+ferxium.1` identifies our patched copy; it is **not an upstream release**.
The original `LICENSE` and `README.md` are retained without changes.

Upstream `index.js` before modification has SHA-256
`01b7d66c854b2fe53ac05c98feb6e0d64722ab8898a778e2d2426a8b468d178f`.
The implementation change backports the complete `index.js` patch from
[upstream PR #58](https://github.com/kornelski/http-cache-semantics/pull/58),
commit `14a8c2ad51740dc39bf3e8f1a11c845a5003f217`, which was still open on
2026-10-03. This is a locally reviewed backport, not a claim of upstream approval.

[GHSA-ch52-4w7c-c8xp](https://github.com/advisories/GHSA-ch52-4w7c-c8xp)
allows request `max-stale` to bypass shared-response reuse restrictions.
The patch centralizes those restrictions and checks them before either a
cache hit or an asynchronous stale-while-revalidate response can be returned.
It preserves upstream `public`/`immutable` cookie opt-ins and ordinary expiry
behavior. It adds no dependencies or network requests.

The root npm override resolves Astro's dependency to this directory, including
on a fresh `npm ci`. Never edit an installed `node_modules` copy or disable the
high-severity audit check. Local file dependencies are not fully assessed by
the npm advisory database; `npm audit` alone does not validate this patch.

Run `npm run test:cache-security` from the repository root. The 31 regression
cases cover bare/finite `max-stale`, Set-Cookie, proxy-revalidate, no-cache,
no-store, private/authenticated responses, stale-while-revalidate,
serialization and 304 revalidation, with allowed-cache behavior as controls.
They exercise the dependency loaded from Astro and assert its identity against
this reviewed copy, so an ignored override cannot produce a passing check.
Eighteen cases fail against the original 4.2.0 implementation.
The patched implementation also passed all 125 upstream compatibility tests
from commit `f01112e954b83cfa8765b633ba880e5e980aa54c` during local validation.

Once an upstream fixed release is available, move the behavioral regressions
to the project's tests directory and update the dependency identity assertion
to that reviewed release. Remove this directory, the direct local dependency
and npm override together, then regenerate the lockfile and rerun the security
tests, audit, frontend builds and browser checks. Do not downgrade Astro to
the old version suggested by `npm audit fix --force`.
