import releases from './releases.json';
export const repository = import.meta.env.PUBLIC_REPOSITORY_URL as string | undefined;
if (repository && !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/.test(repository))
  throw new Error('PUBLIC_REPOSITORY_URL must be a GitHub repository URL');
export const sourceArchive = import.meta.env.PUBLIC_SOURCE_ARCHIVE_URL as string | undefined;
if (sourceArchive && !/^\/downloads\/[\w.-]+\.zip$/.test(sourceArchive))
  throw new Error('PUBLIC_SOURCE_ARCHIVE_URL must be a local downloads ZIP path');
export const sourceLink = repository ?? sourceArchive ?? '/docs/#build';
export interface ReleaseAsset {
  platform: 'windows' | 'macos' | 'linux';
  architecture: string;
  name: string;
  url: string;
  sha256: string;
  signed: boolean;
  kind: 'installer' | 'portable';
}
export const assets = releases.assets as ReleaseAsset[];
for (const asset of assets) {
  if (!/^https:\/\//.test(asset.url) || !/^[a-f0-9]{64}$/.test(asset.sha256))
    throw new Error(`Invalid release asset: ${asset.name}`);
}
export const version = releases.version;
export const releaseStatus = releases.status;
