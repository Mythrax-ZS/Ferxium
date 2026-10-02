// Exercise the real authenticated API with an isolated state/watch directory.
// The marker is harmless and requires a service built with --features yara-engine.
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import assert from 'node:assert/strict';
const root = await mkdtemp(join(tmpdir(), 'ferxium-smoke-'));
const state = join(root, 'state');
const watched = join(root, 'watched');
await mkdir(state);
await mkdir(watched);
await writeFile(
  join(state, 'config.json'),
  JSON.stringify({ protection_enabled: true, watch_paths: [watched] }),
);
const executable = process.env.FERXIUM_SERVICE_BINARY
  ? resolve(process.env.FERXIUM_SERVICE_BINARY)
  : resolve(
      'target/debug',
      process.platform === 'win32' ? 'ferxium-service.exe' : 'ferxium-service',
    );
const service = spawn(executable, ['--data-dir', state], {
  windowsHide: true,
  stdio: ['pipe', 'pipe', 'pipe'],
});
let stderr = '';
let latestStatus;
service.stderr.on('data', (data) => (stderr += data.toString()));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, seconds = 20) {
  for (let i = 0; i < seconds * 10; i++) {
    if (await fn()) return;
    await wait(100);
  }
  // Keep enough local diagnostics to investigate a missed native notification.
  // Never print the discovery record or authorization token.
  const diagnostics = latestStatus && {
    version: latestStatus.version,
    watcher_active: latestStatus.watcher_active,
    yara_enabled: latestStatus.yara_enabled,
    dropped_events: latestStatus.dropped_events,
    scanned_total: latestStatus.scanned_total,
    threats_found: latestStatus.threats.length,
    activity: latestStatus.activity.slice(0, 10),
  };
  throw new Error(
    `Timed out in isolated state ${root}. Service: ${stderr}. Status: ${JSON.stringify(diagnostics)}`,
  );
}
try {
  let discovery;
  await until(async () => {
    try {
      discovery = JSON.parse(await readFile(join(state, 'service.json'), 'utf8'));
      return true;
    } catch {
      return false;
    }
  });
  const base = `http://127.0.0.1:${discovery.port}/v1`;
  const headers = {
    authorization: `Bearer ${discovery.token}`,
    'content-type': 'application/json',
  };
  const status = async () => {
    const response = await fetch(`${base}/status`, { headers });
    assert.equal(response.status, 200);
    latestStatus = await response.json();
    return latestStatus;
  };
  const action = async (body) => {
    const response = await fetch(`${base}/action`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    assert.equal(response.status, 200, await response.text());
  };
  assert.equal((await fetch(`${base}/status`)).status, 401);
  assert.equal(
    (
      await fetch(`${base}/status`, {
        headers: { ...headers, origin: 'https://untrusted.example' },
      })
    ).status,
    403,
  );
  await until(async () => (await status()).watcher_active);
  assert.equal(latestStatus.yara_enabled, true, 'The smoke test requires a YARA-enabled service');
  const marker = join(watched, 'harmless-marker.txt');
  await writeFile(marker, 'FERXIUM_TEST_SIGNATURE_v1');
  let threat;
  await until(async () => {
    threat = (await status()).threats.find((t) => t.path.endsWith('harmless-marker.txt'));
    return !!threat;
  });
  assert.equal(threat.findings[0].method, 'yara');
  // Words only, not a BAT program: verify campaign rules reach the real watcher,
  // status API, and custom-scan engine in the actual packaged protection service.
  const campaign = join(watched, 'harmless-renengine-indicators.txt');
  await writeFile(
    campaign,
    [
      'Harmless static regression fixture; do not execute',
      'MSBUILDENABLEALLPROPERTYFUNCTIONS=1',
      '_czzf',
      'Nancy.csproj',
      'MSBuild.exe',
      'conhost.exe',
      '--headless',
    ].join('\n'),
  );
  await until(async () =>
    (await status()).threats.some(
      (t) =>
        t.path.endsWith('harmless-renengine-indicators.txt') &&
        t.findings.some(
          (f) => f.name === 'FerXium_RenEngine_MSBuild_Launcher' && f.severity === 'high',
        ),
    ),
  );
  await action({ action: 'quarantine', id: threat.id });
  await assert.rejects(access(marker));
  assert.equal((await status()).quarantine[0].source_removed, true);
  const restored = join(root, 'restored-marker.txt');
  await action({ action: 'restore', id: threat.id, destination: restored });
  assert.equal(await readFile(restored, 'utf8'), 'FERXIUM_TEST_SIGNATURE_v1');
  await action({ action: 'delete_quarantine', id: threat.id });
  assert.equal((await status()).quarantine.length, 0);
  await action({ action: 'start_scan', request: { kind: 'custom', paths: [watched] } });
  await until(async () => (await status()).scan?.state === 'completed');
  assert.equal((await status()).scan.errors, 0);
  assert.ok((await status()).scan.threats > 0);
  console.log(
    'Real service smoke passed: auth, native watcher, YARA, RenEngine indicators, quarantine, restore, delete, custom scan.',
  );
  console.log(`Isolated test state retained for inspection: ${root}`);
} finally {
  service.kill();
  await Promise.race([new Promise((r) => service.once('exit', r)), wait(3000)]);
}
