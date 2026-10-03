// Crash only the worker belonging to this isolated, newly spawned supervisor.
// Requires a YARA-enabled service. Use inert marker text, never live malware.
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, readFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join, toNamespacedPath } from 'node:path';

const execute = promisify(execFile);
const windows = process.platform === 'win32';
const binary = resolve(
  process.env.FERXIUM_SERVICE_BINARY ?? `target/debug/ferxium-service${windows ? '.exe' : ''}`,
);
const root = await mkdtemp(join(tmpdir(), 'ferxium-supervisor-'));
const data = join(root, 'state');
const watched = join(root, 'watched');
await mkdir(data);
await mkdir(watched);
await writeFile(
  join(data, 'config.json'),
  JSON.stringify({ protection_enabled: true, watch_paths: [watched] }),
);
const supervisor = spawn(binary, ['--supervise', '--data-dir', data], {
  windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...process.env, RUST_LOG: 'warn' },
});
let logs = '';
let latestStatus;
for (const stream of [supervisor.stdout, supervisor.stderr]) {
  stream.on('data', (chunk) => {
    logs = (logs + chunk.toString()).slice(-2000);
  });
}

const delay = (ms) => new Promise((done) => setTimeout(done, ms));
async function until(check, description) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    try {
      const result = await check();
      if (result) return result;
    } catch {
      /* worker restarting */
    }
    await delay(100);
  }
  const diagnostic = latestStatus && {
    watcher_active: latestStatus.watcher_active,
    yara_enabled: latestStatus.yara_enabled,
    scanned_total: latestStatus.scanned_total,
    monitoring: latestStatus.monitoring,
    findings: latestStatus.threats.slice(0, 10).map((t) => ({ path: t.path, status: t.status })),
  };
  throw new Error(
    `Timed out: ${description}. Supervisor logs: ${logs}. Status: ${JSON.stringify(diagnostic)}`,
  );
}
async function discovery() {
  return JSON.parse(await readFile(join(data, 'service.json'), 'utf8'));
}
async function heartbeat() {
  return JSON.parse(await readFile(join(data, 'supervisor.json'), 'utf8'));
}
async function status(connection) {
  const response = await fetch(`http://127.0.0.1:${connection.port}/v1/status`, {
    headers: { authorization: `Bearer ${connection.token}` },
    signal: AbortSignal.timeout(2000),
  });
  assert.ok(response.ok, 'Authenticated status should succeed');
  latestStatus = await response.json();
  return latestStatus;
}
async function exited(child) {
  if (child.exitCode !== null || child.signalCode !== null) return child.exitCode;
  return new Promise((done, reject) => {
    child.once('exit', done);
    child.once('error', reject);
  });
}

try {
  let connection = await until(async () => {
    const candidate = await discovery();
    const beat = await heartbeat();
    return (
      beat.pid === supervisor.pid &&
      beat.worker_pid === candidate.pid &&
      (await status(candidate)).watcher_active &&
      candidate
    );
  }, 'supervised worker startup');
  assert.equal(
    (await status(connection)).yara_enabled,
    true,
    'Build the service with --features yara-engine',
  );
  const duplicate = spawn(binary, ['--supervise', '--data-dir', data], {
    windowsHide: true,
    stdio: 'ignore',
  });
  assert.equal(
    await exited(duplicate),
    0,
    'A second supervisor should exit without taking ownership',
  );
  assert.equal((await heartbeat()).pid, supervisor.pid);

  for (let crash = 1; crash <= 2; crash++) {
    const beat = await heartbeat();
    assert.equal(beat.pid, supervisor.pid);
    assert.equal(beat.worker_pid, connection.pid);
    assert.equal(supervisor.exitCode, null);
    // Validate direct parent ownership immediately before the deliberate crash.
    if (windows) {
      const powershell = join(
        process.env.SystemRoot ?? 'C:\\Windows',
        'System32/WindowsPowerShell/v1.0/powershell.exe',
      );
      await execute(
        powershell,
        [
          '-NoProfile',
          '-Command',
          `$ownedWorker = Get-CimInstance Win32_Process -Filter "ProcessId = ${connection.pid}"; if (-not $ownedWorker -or $ownedWorker.ParentProcessId -ne ${supervisor.pid}) { throw 'Worker ownership changed' }; Stop-Process -Id ${connection.pid} -Force`,
        ],
        { windowsHide: true },
      );
    } else {
      const { stdout } = await execute('/bin/ps', ['-o', 'ppid=', '-p', String(connection.pid)]);
      assert.equal(Number(stdout.trim()), supervisor.pid);
      process.kill(connection.pid, 'SIGKILL');
    }
    const previous = connection;
    connection = await until(async () => {
      const candidate = await discovery();
      if (candidate.pid === previous.pid) return false;
      const beat = await heartbeat();
      return (
        beat.worker_pid === candidate.pid && (await status(candidate)).watcher_active && candidate
      );
    }, `worker recovery after crash ${crash}`);
    assert.ok(connection.token !== previous.token, 'IPC credentials must rotate after a restart');
    assert.equal((await heartbeat()).restart_count, crash);
    const fixture = join(watched, `inert-after-restart-${crash}.txt`);
    await writeFile(fixture, 'FERXIUM_TEST_SIGNATURE_v1');
    const canonicalFixture = toNamespacedPath(await realpath(fixture));
    await until(async () => {
      const candidates = (await status(connection)).threats.filter((t) => t.status === 'pending');
      const matches = await Promise.all(
        candidates.map(async (t) => {
          try {
            return toNamespacedPath(await realpath(t.path)) === canonicalFixture;
          } catch {
            return false;
          }
        }),
      );
      return matches.some(Boolean);
    }, 'file detection after recovery');
  }
  await execute(binary, ['--stop', '--data-dir', data], { windowsHide: true, timeout: 20_000 });
  assert.equal(await exited(supervisor), 0, 'Intentional stop should be clean');
  await delay(1500);
  assert.equal((await heartbeat()).state, 'stopped');
  console.log(
    'Supervisor smoke passed: duplicate ownership rejected; two crashes recover; IPC tokens rotate; file detection resumes; intentional stop does not restart.',
  );
  console.log(`Isolated test state retained: ${data}`);
} finally {
  if (supervisor.exitCode === null && supervisor.signalCode === null) {
    await execute(binary, ['--stop', '--data-dir', data], {
      windowsHide: true,
      timeout: 20_000,
    }).catch(() => {});
    if (supervisor.exitCode === null && supervisor.signalCode === null) supervisor.kill();
  }
}
