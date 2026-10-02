// Bundled signatures must not turn the installed scanner into its own threat.
// Scan real release binaries with the YARA-enabled release CLI before publishing.
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';

const suffix = process.platform === 'win32' ? '.exe' : '';
const cli = resolve(`target/release/ferxium-cli${suffix}`);
for (const name of ['ferxium-cli', 'ferxium-service', 'ferxium-desktop']) {
  const binary = resolve(`target/release/${name}${suffix}`);
  const result = spawnSync(cli, ['scan', binary], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${name} self-scan failed: ${result.stdout} ${result.stderr}`);
  const lines = result.stdout.trim().split('\n');
  assert.equal(lines.length, 1, `Expected one checked binary: ${name}`);
  assert.equal(JSON.parse(lines[0]).result.outcome, 'clean', `Binary was not checked: ${name}`);
}
console.log('Release self-scan passed: desktop, service, and CLI are clean under bundled rules.');
