// Build companion binaries on the native runner and give Tauri target-qualified names.
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
function run(command, args, capture = false) {
  const result = spawnSync(command, args, {
    cwd: root,
    windowsHide: true,
    encoding: 'utf8',
    stdio: capture ? 'pipe' : 'inherit',
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed (${result.status})`);
  return result.stdout;
}
const host = run('rustc', ['-vV'], true)
  .match(/^host: (.+)$/m)?.[1]
  ?.trim();
if (!host) throw new Error('Could not identify the native Rust build target');
const target = process.env.TAURI_ENV_TARGET_TRIPLE || host;
if (target !== host)
  throw new Error(`Use a native ${target} runner to build the companion service`);
if (process.argv.includes('--build')) {
  run('cargo', [
    'build',
    '--locked',
    '--release',
    '-p',
    'ferxium-service',
    '-p',
    'ferxium-cli',
    '--features',
    'ferxium-service/yara-engine,ferxium-cli/yara-engine',
  ]);
}
const extension = host.includes('windows') ? '.exe' : '';
const destination = join(root, 'apps/desktop/src-tauri/binaries');
mkdirSync(destination, { recursive: true });
for (const name of ['ferxium-service', 'ferxium-cli']) {
  copyFileSync(
    join(root, 'target/release', `${name}${extension}`),
    join(destination, `${name}-${host}${extension}`),
  );
}
console.log(`Prepared native service and CLI sidecars for ${host}`);
