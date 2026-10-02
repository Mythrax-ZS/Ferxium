# Security policy

Version 0.1.x is a development source preview. No independently validated or certified production release exists yet.

Do not publish exploitable security details or live malware in a public issue. Once this code is hosted on GitHub, use the repository's **Security → Report a vulnerability** private advisory workflow. The maintainer must enable that workflow before launch. If it is unavailable, obtain a private maintainer contact from that repository before sharing exploit details; no contact address is invented here.

Useful reports include platform, affected version/commit, trust boundary, a harmless reproduction, observed impact, and proposed mitigations. Never test against systems without authorization.

The current trust model is documented in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md). File watchers are not execution prevention, and user-scoped storage is not a boundary against malicious code running as the same user. Do not run this prototype as a privileged service exposed to lower-trust users.
