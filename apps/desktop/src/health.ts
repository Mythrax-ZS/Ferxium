import type { Status } from './types';

export function protectionPresentation(status: Status | null, offline: boolean) {
  if (offline || !status || !status.protection_enabled) {
    return {
      className: 'inactive',
      label: 'FILE MONITORING INACTIVE',
      title: 'Your protection.\nReady when you are.',
      message:
        'Connect the protection service and enable file monitoring to watch your selected folders.',
    };
  }
  if (!status.watcher_active || status.monitoring?.health === 'degraded') {
    return {
      className: 'degraded',
      label: 'FILE MONITORING DEGRADED',
      title: 'Monitoring needs\nsome attention.',
      message:
        'Some changes may be unchecked. Automatic recovery retries unavailable folders and files; review the monitoring health below.',
    };
  }
  if (['starting', 'recovering'].includes(status.monitoring?.health ?? '')) {
    return {
      className: 'recovering',
      label: 'FILE MONITORING RECOVERING',
      title: 'Checking changes.\nRestoring coverage.',
      message:
        'File monitoring continues while watched folders are checked for missed changes. Your files remain on this device.',
    };
  }
  return {
    className: 'active',
    label: 'FILE MONITORING ACTIVE',
    title: 'Watching over\nyour digital world.',
    message:
      'Local-first scanning is watching for file changes.\nYour files stay yours. Your data stays here.',
  };
}
