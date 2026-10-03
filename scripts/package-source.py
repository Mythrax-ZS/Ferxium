"""Package publishable project sources; exclude secrets and generated state.

Run from any directory: python scripts/package-source.py OUTPUT_DIRECTORY
Only explicitly allowed source trees and file types can enter the archive.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

root = Path(__file__).resolve().parent.parent
version = json.loads((root / "apps/website/src/data/releases.json").read_text())["version"]
output = Path(sys.argv[1]).resolve()
output.mkdir(parents=True, exist_ok=True)
archive = output / f"ferxium-{version}-source.zip"
trees = {".github", "apps", "crates", "docs", "packaging", "scripts", "signatures", "tests"}
root_files = {
    ".gitignore", ".prettierignore", ".prettierrc.json", "CONTRIBUTING.md",
    "Cargo.lock", "Cargo.toml", "LICENSE", "README.md", "SECURITY.md",
    "package-lock.json", "package.json", "playwright.config.ts", "rustfmt.toml",
}
# The build dependency backport and its original BSD license must accompany the
# npm override. Keep this an explicit tree rather than admitting arbitrary vendor files.
vendor_tree = "vendor/http-cache-semantics"
extensions = {
    ".rs", ".toml", ".json", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".css", ".html",
    ".astro", ".svg", ".png", ".ico", ".icns", ".md", ".yml", ".yaml", ".yar",
    ".py", ".ps1", ".sh", ".plist", ".service", ".txt", ".caddy",
}
excluded = {"node_modules", "target", "dist", ".astro", "gen", "artifacts", "android", "ios"}
paths = subprocess.check_output(
    ["rg", "--files", "--hidden", "-g", "!.git", "-g", "!node_modules", "-g", "!target"],
    cwd=root, text=True,
).splitlines()
count = 0
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
    for relative in sorted(paths):
        path = root / relative.replace("\\", "/")
        rel = path.relative_to(root)
        if any(part in excluded for part in rel.parts):
            continue
        if rel.as_posix() not in root_files:
            is_cache_backport = rel.as_posix().startswith(vendor_tree + "/")
            if rel.parts[0] not in trees and not is_cache_backport:
                continue
            allowed_name = path.name == ".env.example" or (is_cache_backport and path.name == "LICENSE")
            if not allowed_name and (path.name.startswith(".env") or path.suffix not in extensions):
                continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"Refusing non-regular source: {rel}")
        bundle.write(path, f"ferxium-{version}/{rel.as_posix()}")
        count += 1
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_suffix(".zip.sha256").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
print(f"Packaged {count} source files: {archive.name} ({archive.stat().st_size:,} bytes)")
print(f"SHA-256: {digest}")
