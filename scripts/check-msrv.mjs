import { execFileSync } from 'node:child_process';
const metadata = JSON.parse(
  execFileSync('cargo', ['metadata', '--format-version', '1', '--offline'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  }),
);
const packages = metadata.packages
  .filter((p) => p.rust_version)
  .sort((a, b) => Number(b.rust_version.split('.')[1]) - Number(a.rust_version.split('.')[1]));
for (const pkg of packages.slice(0, 8))
  console.log(`${pkg.name} ${pkg.version}: Rust ${pkg.rust_version}`);
