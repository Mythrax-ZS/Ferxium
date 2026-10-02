"""Copy real native bundles and emit checksums plus a website release fragment."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import sys

root = Path(__file__).resolve().parent.parent
version = json.loads((root / 'apps/desktop/src-tauri/tauri.conf.json').read_text())['version']
system = {'Windows': 'windows', 'Darwin': 'macos', 'Linux': 'linux'}[platform.system()]
architecture = 'aarch64' if platform.machine().lower() in ('arm64', 'aarch64') else 'x86_64'
extension = {'windows': 'exe', 'macos': 'dmg', 'linux': 'deb'}[system]
bundles = list((root / 'target/release/bundle').rglob(f'*.{extension}'))
assert len(bundles) == 1, f'Expected one native {extension} bundle, found {bundles}'
destination = root / 'artifacts/release'
destination.mkdir(parents=True, exist_ok=True)
filename = f'FerXium-{version}-{system}-{architecture}' + ('-setup' if system == 'windows' else '') + f'.{extension}'
output = destination / filename
shutil.copyfile(bundles[0], output)
digest = hashlib.sha256(output.read_bytes()).hexdigest()
(destination / f'{filename}.sha256').write_text(f'{digest}  {filename}\n', encoding='ascii')
manifest = [{
    'platform': system, 'architecture': architecture, 'name': filename,
    'url': f'https://ferxium.org/downloads/{filename}', 'sha256': digest,
    'signed': False, 'kind': 'installer',
}]
(destination / f'{system}-{architecture}.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(f'Native release: {filename} ({output.stat().st_size:,} bytes)')
print(f'SHA-256: {digest}')
