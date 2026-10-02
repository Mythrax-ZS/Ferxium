"""Verify downloaded release assets before updating the site's download manifest.

python scripts/import-release.py DIRECTORY
DIRECTORY holds GitHub release platform JSON fragments and their native packages.
"""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent.parent
directory = Path(sys.argv[1]).resolve()
assets = []
for fragment in sorted(directory.glob('*-*.json')):
    for asset in json.loads(fragment.read_text()):
        path = directory / asset['name']
        assert path.parent == directory and path.is_file(), 'Missing or invalid native asset path'
        assert hashlib.sha256(path.read_bytes()).hexdigest() == asset['sha256'], f'Checksum mismatch: {path.name}'
        assert asset['url'] == f"https://ferxium.org/downloads/{path.name}", 'Unexpected asset host'
        assert asset['platform'] in {'windows', 'linux', 'macos'}
        assert isinstance(asset['signed'], bool)
        assets.append(asset)
assert assets, 'No verified release fragments found'
manifest_path = root / 'apps/website/src/data/releases.json'
manifest = json.loads(manifest_path.read_text())
manifest.update(status='preview', assets=assets)
manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
print(f'Imported {len(assets)} verified native release assets')
