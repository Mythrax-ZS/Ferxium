import { useEffect, useState } from 'react';
import { Bell, Power } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import { native } from './api';

interface Preferences {
  notifications_enabled: boolean;
  start_at_login: boolean;
  startup_available: boolean;
  supervisor_running: boolean;
  restart_count: number;
  supervisor_state: string;
  last_notification_error: string | null;
}

export function DesktopSettings() {
  const [preferences, setPreferences] = useState<Preferences | null>(
    native
      ? null
      : {
          notifications_enabled: true,
          start_at_login: false,
          startup_available: false,
          supervisor_running: false,
          restart_count: 0,
          supervisor_state: 'demo',
          last_notification_error: null,
        },
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [pollError, setPollError] = useState('');
  const [notice, setNotice] = useState('');
  useEffect(() => {
    if (!native) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const next = await invoke<Preferences>('desktop_preferences');
        if (alive) {
          setPreferences(next);
          setPollError('');
        }
      } catch (e) {
        if (alive) setPollError(String(e));
      } finally {
        if (alive) timer = setTimeout(poll, 2000);
      }
    }
    void poll();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, []);

  async function change(setting: 'notifications' | 'start_at_login', enabled: boolean) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      if (native) {
        await invoke('set_desktop_preference', { change: { setting, enabled } });
        setPreferences(await invoke<Preferences>('desktop_preferences'));
      } else {
        setPreferences((current) =>
          current ? { ...current, notifications_enabled: enabled } : current,
        );
        setNotice('Browser preview changes do not affect your computer.');
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function testNotification() {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await invoke('test_notification');
      setNotice(
        'Notification request sent. If it does not appear, check your operating system’s notification settings.',
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section
      className="panel settings-panel desktop-preferences"
      aria-label="Background protection preferences"
    >
      <div className="panel-heading">
        <h3>Background protection & alerts</h3>
        <Bell size={18} />
      </div>
      <div className="setting-row">
        <div>
          <h4>Threat notifications</h4>
          <p>Show native alerts for new findings, including while FerXium is in the tray.</p>
        </div>
        <button
          type="button"
          className={`toggle ${preferences?.notifications_enabled ? 'on' : ''}`}
          role="switch"
          aria-label="Threat notifications"
          aria-checked={!!preferences?.notifications_enabled}
          disabled={busy || !preferences}
          onClick={() => void change('notifications', !preferences?.notifications_enabled)}
        >
          <span />
        </button>
      </div>
      <button
        type="button"
        className="button secondary"
        disabled={!native || busy || !preferences?.notifications_enabled}
        onClick={() => void testNotification()}
      >
        <Bell size={16} />
        Send test notification
      </button>
      <div className="setting-row">
        <div>
          <h4>Start at login</h4>
          <p>Start FerXium quietly in the tray when you sign in. Applies to your account only.</p>
        </div>
        <button
          type="button"
          className={`toggle ${preferences?.start_at_login ? 'on' : ''}`}
          role="switch"
          aria-label="Start at login"
          aria-checked={!!preferences?.start_at_login}
          disabled={busy || !preferences?.startup_available}
          onClick={() => void change('start_at_login', !preferences?.start_at_login)}
        >
          <span />
        </button>
      </div>
      {!native && (
        <p className="muted-copy">
          Install the desktop app to configure login startup and send native notifications.
        </p>
      )}
      {native && preferences && !preferences.startup_available && (
        <p className="muted-copy">
          Login startup is available in installed release builds using normal application state.
        </p>
      )}
      <div className="setting-row">
        <div>
          <h4>Automatic service recovery</h4>
          <p>
            The separate restart monitor recovers a crashed scanner, including after the desktop
            exits.
          </p>
        </div>
        <span className="subtle-tag">
          <Power size={12} />{' '}
          {native
            ? preferences?.supervisor_running
              ? 'MONITOR RUNNING'
              : 'MONITOR UNAVAILABLE'
            : 'DEMO'}
        </span>
      </div>
      {!!preferences?.restart_count && (
        <p className="muted-copy">{preferences.restart_count} restart attempts this session.</p>
      )}
      <p className="muted-copy">
        Full file paths are omitted from system alerts. Focus modes and operating system settings
        can suppress popups. Explicitly quitting the desktop stops notifications; scanning and
        recovery continue.
      </p>
      {(error || pollError) && (
        <p role="alert" className="danger">
          {error || pollError}
        </p>
      )}
      {preferences?.last_notification_error && (
        <p role="alert" className="danger">
          {preferences.last_notification_error}
        </p>
      )}
      {notice && <p role="status">{notice}</p>}
    </section>
  );
}
