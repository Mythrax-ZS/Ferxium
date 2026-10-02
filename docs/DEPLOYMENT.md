# Deploying ferxium.org

The marketing website is static. Build on a development machine and upload only
`apps/website/dist`, never the entire working tree. Credentials, development
state, native build artifacts, and environment files do not belong in a web root.

```powershell
$env:SITE_URL = 'https://ferxium.org'
$env:PUBLIC_SOURCE_ARCHIVE_URL = '/downloads/ferxium-0.1.0-source.zip'
# Set PUBLIC_REPOSITORY_URL only when a real public repository exists.
npm run build -w @ferxium/website
python scripts/package-source.py apps/website/dist/downloads
```

The source package includes the Rust crates, desktop and website sources, rules,
MIT license, documentation, and lockfiles. It excludes secrets and generated
directories. The accompanying checksum detects transfer corruption; it is not a
publisher signature. Signed installers remain a separate release milestone.

DNS records at the domain provider:

| Type  | Name | Value          |
| ----- | ---- | -------------- |
| A     | @    | 95.217.178.184 |
| CNAME | www  | ferxium.org    |

Caddy serves the site and obtains/renews HTTPS certificates. Keep ports 80 and 443
reachable. Add the reviewed [site configuration](../packaging/ferxium.org.caddy)
as `/etc/caddy/sites/ferxium.org.caddy` and import that exact file from the existing
`/etc/caddy/Caddyfile`. Back up the existing configuration before changing it.
Run `caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile` before
`systemctl reload caddy`; validation or reload failure must restore the backup.

Upload into a new `/var/www/ferxium.org/releases/RELEASE_ID` directory. Use root
ownership, readable files and traversable directories for Caddy, without granting
the web process write access. Switch `/var/www/ferxium.org/current` using an atomic
symlink replacement only after validating the release contents. Keep previous
releases for rollback. Check the homepage, all six pages, missing-page status,
source checksum, HTTPS certificate, HTTP redirect, and www redirect after publishing.

Do not enable access logging or third-party analytics for this site. Configure a
real public repository URL when ready; until then, the deployed site links to the
downloadable source ZIP.
