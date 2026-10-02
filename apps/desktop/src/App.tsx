import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Bell,
  Check,
  CheckCheck,
  ChevronRight,
  CircleHelp,
  Clock3,
  Cpu,
  FileSearch,
  Folder,
  HardDrive,
  History,
  LayoutDashboard,
  LockKeyhole,
  Moon,
  Pause,
  Play,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  ShieldOff,
  Sun,
  X,
  Zap,
} from 'lucide-react';
import { open, save } from '@tauri-apps/plugin-dialog';
import { listen } from '@tauri-apps/api/event';
import { getStatus, native, sendAction } from './api';
import { demo } from './demo';
import type { Action, Config, ScanKind, Status, Threat } from './types';

type Page = 'Dashboard' | 'Scans' | 'Quarantine' | 'Settings' | 'History';
const navigation = [
  { name: 'Dashboard', icon: LayoutDashboard },
  { name: 'Scans', icon: FileSearch },
  { name: 'Quarantine', icon: LockKeyhole },
  { name: 'Settings', icon: Settings2 },
  { name: 'History', icon: History },
] as const;
const formatDate = (value?: string | null) =>
  value
    ? new Date(value).toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    : 'No scans yet';
const count = (n: number) => n.toLocaleString();
const bytes = (n: number) => `${(n / 1024 / 1024).toFixed(1)} MB`;

function Logo({ large = false }: { large?: boolean }) {
  return (
    <div className={`brand ${large ? 'large' : ''}`}>
      <span className="brand-mark">
        <ShieldCheck size={large ? 30 : 25} />
      </span>
      <span>
        Fer<span className="brand-weight">Xium</span>
        <small>PROTECTION, REIMAGINED</small>
      </span>
    </div>
  );
}
function Toggle({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      className={`toggle ${checked ? 'on' : ''}`}
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span />
    </button>
  );
}
function Empty({
  icon,
  heading,
  children,
}: {
  icon: ReactNode;
  heading: string;
  children: ReactNode;
}) {
  return (
    <div className="empty">
      {icon}
      <h3>{heading}</h3>
      <p>{children}</p>
    </div>
  );
}

export default function App() {
  const [page, setPage] = useState<Page>('Dashboard');
  const [status, setStatus] = useState<Status | null>(native ? null : structuredClone(demo));
  const [offline, setOffline] = useState(native);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [detail, setDetail] = useState<Threat | null>(null);
  const detailDialog = useRef<HTMLDialogElement>(null);
  const [theme, setTheme] = useState(() => localStorage.getItem('ferxium-theme') ?? 'dark');
  const [custom, setCustom] = useState('');
  const demoProgress = useRef(0);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('ferxium-theme', theme);
  }, [theme]);
  useEffect(() => {
    if (!native) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const next = await getStatus();
        if (alive) {
          setStatus(next);
          setOffline(false);
        }
      } catch {
        if (alive) setOffline(true);
      } finally {
        if (alive) timer = setTimeout(poll, 1000);
      }
    };
    void poll();
    const unlisten = listen<string>('service-error', (e) => {
      if (alive) setError(e.payload);
    });
    return () => {
      alive = false;
      clearTimeout(timer);
      void unlisten.then((fn) => fn());
    };
  }, []);
  useEffect(() => {
    if (detail) detailDialog.current?.showModal();
  }, [detail]);
  useEffect(() => {
    if (native) return;
    const timer = setInterval(
      () =>
        setStatus((s) => {
          if (!s?.scan || !['running', 'enumerating'].includes(s.scan.state)) return s;
          demoProgress.current += 620;
          const n = Math.min(18429, demoProgress.current);
          const done = n === 18429;
          const scan = {
            ...s.scan,
            scanned: n,
            total_files: 18429,
            state: done ? 'completed' : 'running',
            elapsed_seconds: s.scan.elapsed_seconds + 1,
            estimated_remaining_seconds: done ? null : Math.ceil((18429 - n) / 620),
            finished_at: done ? new Date().toISOString() : null,
          };
          return {
            ...s,
            scan,
            scanned_total: s.scanned_total + 620,
            history: done ? [scan, ...s.history] : s.history,
          };
        }),
      1000,
    );
    return () => clearInterval(timer);
  }, []);
  const active = !!status?.protection_enabled && !!status?.watcher_active && !offline;
  const scanActive =
    !!status?.scan && ['running', 'paused', 'enumerating'].includes(status.scan.state);
  const pending = status?.threats.filter((t) => t.status === 'pending') ?? [];

  async function act(action: Action) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      if (native) {
        await sendAction(action);
        setStatus(await getStatus());
      } else {
        setStatus((s) => {
          if (!s) return s;
          if (action.action === 'set_protection')
            return {
              ...s,
              protection_enabled: action.enabled,
              watcher_active: action.enabled,
              config: { ...s.config, protection_enabled: action.enabled },
            };
          if (action.action === 'save_config')
            return {
              ...s,
              config: action.config,
              protection_enabled: action.config.protection_enabled,
            };
          if (action.action === 'start_scan') {
            demoProgress.current = 0;
            return {
              ...s,
              scan: {
                id: crypto.randomUUID(),
                kind: action.request.kind,
                state: 'running',
                scanned: 0,
                total_files: 18429,
                skipped: 0,
                errors: 0,
                threats: 0,
                current_path: 'Illustrative browser preview',
                started_at: new Date().toISOString(),
                finished_at: null,
                elapsed_seconds: 0,
                estimated_remaining_seconds: 30,
              },
            };
          }
          if (['pause_scan', 'resume_scan', 'cancel_scan'].includes(action.action) && s.scan)
            return {
              ...s,
              scan: {
                ...s.scan,
                state:
                  action.action === 'pause_scan'
                    ? 'paused'
                    : action.action === 'resume_scan'
                      ? 'running'
                      : 'cancelled',
              },
            };
          return s;
        });
        setNotice('Demo updated. Browser preview does not access or protect files.');
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function start(kind: ScanKind) {
    let paths: string[] = [];
    if (kind === 'custom') {
      if (native) {
        const picked = await open({
          directory: true,
          multiple: true,
          title: 'Select folders to scan',
        });
        if (!picked) return;
        paths = Array.isArray(picked) ? picked : [picked];
      } else {
        if (!custom.trim()) {
          setError('Enter a folder path for the demo scan.');
          return;
        }
        paths = [custom.trim()];
      }
    }
    await act({ action: 'start_scan', request: { kind, paths } });
  }
  async function restore(id: string, path: string) {
    const destination = native
      ? await save({
          title: 'Restore file — restored files may be detected again',
          defaultPath: path,
        })
      : null;
    if (destination) await act({ action: 'restore', id, destination });
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Logo />
        <div className="workspace-tag">
          <span className="tiny-dot" /> PERSONAL PROTECTION
        </div>
        <nav aria-label="Main navigation">
          {navigation.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={`nav-item ${page === name ? 'selected' : ''}`}
              aria-current={page === name ? 'page' : undefined}
              aria-label={name}
              onClick={() => setPage(name)}
            >
              <Icon size={19} />
              <span>{name}</span>
              {name === 'Quarantine' && !!status?.quarantine.length && (
                <span className="nav-count">{status.quarantine.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-note">
            <LockKeyhole size={19} />
            <div>
              Your privacy. Always.<small>No telemetry. No compromises.</small>
            </div>
          </div>
          <span className="version">
            FerXium v{status?.version ?? '0.1.0'} <span>MIT LICENSE</span>
          </span>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            Your workspace <ChevronRight size={14} />
            <strong>{page}</strong>
          </div>
          <div className="topbar-actions">
            {!native && <span className="demo-tag">INTERACTIVE DEMO</span>}
            <span className="connection">
              <span className={`tiny-dot ${offline ? 'muted' : ''}`} />
              {offline ? 'Service offline' : native ? 'Local service connected' : 'Preview mode'}
            </span>
            <button
              className="icon-button"
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            >
              {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <button
              className="icon-button notification"
              aria-label="Review notifications"
              onClick={() => setPage('History')}
            >
              <Bell size={18} />
              {pending.length > 0 && <i />}
            </button>
            <div className="avatar" aria-label="Personal device">
              FX
            </div>
          </div>
        </header>
        <main id="main-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">YOUR DEVICE. YOUR PEACE OF MIND.</div>
              <h1>{page === 'Dashboard' ? 'Protection at a glance' : page}</h1>
              <p>
                {
                  {
                    Dashboard: 'A little less worry. A lot more confidence.',
                    Scans: 'Choose the right check for your peace of mind.',
                    Quarantine: 'Potential threats, safely held and under your control.',
                    Settings: 'Protection that works on your terms.',
                    History: 'A clear record of what your protection has checked.',
                  }[page]
                }
              </p>
            </div>
            <span className="free-pill">
              <Check size={13} /> 100% FREE. FOREVER.
            </span>
          </div>
          {offline && (
            <div className="banner warning" role="status">
              <ShieldOff size={20} />
              <div>
                <strong>Protection service is offline</strong>
                <p>
                  Start <code>ferxium-service</code> as your normal user. Live protection status is
                  unavailable.
                </p>
              </div>
            </div>
          )}
          {error && (
            <div className="banner error" role="alert">
              {error}
              <button
                className="icon-button"
                aria-label="Dismiss error"
                onClick={() => setError('')}
              >
                <X size={17} />
              </button>
            </div>
          )}
          {notice && (
            <div className="banner" role="status">
              {notice}
              <button
                className="icon-button"
                aria-label="Dismiss message"
                onClick={() => setNotice('')}
              >
                <X size={17} />
              </button>
            </div>
          )}

          {page === 'Dashboard' && (
            <>
              <section className={`protection-hero ${active ? 'active' : ''}`}>
                <div className="hero-copy">
                  <div className="status-label">
                    <span className="tiny-dot" />
                    {active ? 'FILE MONITORING ACTIVE' : 'FILE MONITORING INACTIVE'}
                  </div>
                  <h2>
                    {active
                      ? 'Watching over\nyour digital world.'
                      : 'Your protection.\nReady when you are.'}
                  </h2>
                  <p>
                    {active
                      ? 'Local-first scanning is watching for file changes.\nYour files stay yours. Your data stays here.'
                      : 'Connect the protection service and enable file monitoring to watch your selected folders.'}
                  </p>
                  <div className="hero-actions">
                    <button
                      className="button primary"
                      disabled={busy || scanActive || offline}
                      onClick={() => void start('quick')}
                    >
                      <Zap size={17} />
                      Run quick scan <ArrowRight size={16} />
                    </button>
                    <button className="text-button" onClick={() => setPage('Scans')}>
                      Explore scan options <ChevronRight size={15} />
                    </button>
                  </div>
                </div>
                <div className="shield-scene" aria-hidden="true">
                  <div className="orbit orbit-one" />
                  <div className="orbit orbit-two" />
                  <div className="shield-grid" />
                  <div className="big-shield">
                    <Shield size={155} strokeWidth={0.8} />
                    <Check size={59} strokeWidth={2.5} />
                  </div>
                  <span className="shield-spark s1" />
                  <span className="shield-spark s2" />
                  <span className="shield-spark s3" />
                  <div className="secure-chip">
                    <LockKeyhole size={13} /> LOCAL. PRIVATE. YOURS.
                  </div>
                </div>
              </section>
              <div className="stats-grid">
                <Stat
                  icon={<ShieldCheck />}
                  label="Files checked"
                  value={count(status?.scanned_total ?? 0)}
                  note="Across your local scans"
                />
                <Stat
                  icon={<Clock3 />}
                  label="Last scan"
                  value={
                    status?.history[0]
                      ? formatDate(status.history[0].finished_at)
                      : 'Not yet scanned'
                  }
                  note={
                    status?.history[0]
                      ? `${count(status.history[0].scanned)} files · ${status.history[0].errors} read errors`
                      : 'Run your first quick scan'
                  }
                  compact
                />
                <Stat
                  icon={<LockKeyhole />}
                  label="Awaiting review"
                  value={String(pending.length).padStart(2, '0')}
                  note={pending.length ? 'Review potential threats below' : 'No pending detections'}
                  warning={pending.length > 0}
                />
              </div>
              {scanActive && status?.scan && <ScanCard scan={status.scan} act={act} busy={busy} />}
              {!!pending.length && (
                <ThreatList threats={pending} detail={setDetail} act={act} busy={busy} />
              )}
              <div className="dashboard-lower">
                <section className="panel">
                  <div className="panel-heading">
                    <h3>Protection layers</h3>
                    <span className="subtle-tag">LOCAL ENGINE</span>
                  </div>
                  <Layer
                    icon={<Activity />}
                    title="Real-time file monitoring"
                    description={`${status?.watched_roots.length ?? 0} folders · native filesystem events`}
                    enabled={active}
                  />
                  <Layer
                    icon={<FileSearch />}
                    title="Signature detection"
                    description={`SHA-256 database v${status?.signature_version ?? 1}${status?.yara_enabled ? ' + YARA rules' : ''}`}
                    enabled={!offline}
                  />
                  <Layer
                    icon={<Cpu />}
                    title="Heuristic analysis"
                    description="Suspicious script patterns flagged for review"
                    enabled={!offline && !!status?.config.heuristics_enabled}
                  />
                  <div className="panel-foot">
                    <CircleHelp size={14} />
                    File monitoring observes changes; it does not block execution.
                  </div>
                </section>
                <section className="panel activity-panel">
                  <div className="panel-heading">
                    <h3>Recent activity</h3>
                    <button className="text-button small" onClick={() => setPage('History')}>
                      View all <ArrowRight size={14} />
                    </button>
                  </div>
                  <div className="activity-feed">
                    {status?.activity.slice(0, 4).map((item, i) => (
                      <div className="activity-item" key={`${item.at}-${i}`}>
                        <span className={`activity-bullet ${item.level}`}>
                          <Check size={11} />
                        </span>
                        <div>
                          <p>{item.message}</p>
                          <time>{formatDate(item.at)}</time>
                        </div>
                      </div>
                    ))}
                    {!status?.activity.length && (
                      <p className="muted-copy">
                        Activity appears here when the local service is running.
                      </p>
                    )}
                  </div>
                </section>
              </div>
              <section className="panel monitoring-summary" aria-label="Local monitoring summary">
                <div>
                  <Cpu size={16} />
                  <span>
                    <strong>{status?.process_count ?? 0}</strong> processes observed
                  </span>
                </div>
                <div>
                  <Activity size={16} />
                  <span>
                    <strong>{status?.established_connections ?? '—'}</strong> TCP connections
                    sampled
                  </span>
                </div>
                <div>
                  <ArrowDownToLine size={16} />
                  <span>
                    {bytes(status?.network_received ?? 0)} received ·{' '}
                    {bytes(status?.network_transmitted ?? 0)} sent
                  </span>
                </div>
              </section>
              {!!status?.dropped_events && (
                <div className="banner warning" role="status">
                  <CircleHelp size={18} />
                  {status.dropped_events} monitoring events were dropped or errored. Run a scan of
                  your monitored folders to check missed changes.
                </div>
              )}
              <div className="philosophy-strip">
                <span className="little-shield">
                  <ShieldCheck size={21} />
                </span>
                <p>
                  <strong>Powerful protection. Nothing to sell.</strong>
                  <span>Open source. No subscriptions. No tracking. Just your peace of mind.</span>
                </p>
                <span className="subtle-tag">BUILT IN RUST</span>
              </div>
            </>
          )}
          {page === 'Scans' && (
            <>
              <div className="scan-options">
                {(
                  [
                    {
                      kind: 'quick',
                      icon: Zap,
                      title: 'Quick scan',
                      text: 'Running executables, startup folders, downloads, and common browser extension locations.',
                      tag: 'THE EVERYDAY CHECK',
                    },
                    {
                      kind: 'full',
                      icon: HardDrive,
                      title: 'Full scan',
                      text: 'All mounted local volumes accessible to your user. Large and excluded files are reported as skipped.',
                      tag: 'THE THOROUGH CHECK',
                    },
                    {
                      kind: 'custom',
                      icon: Folder,
                      title: 'Custom scan',
                      text: 'Choose folders or drives. A focused check for exactly what you want to review.',
                      tag: 'THE PERSONAL CHECK',
                    },
                  ] as const
                ).map(({ kind, icon: Icon, title, text, tag }) => (
                  <section className="panel scan-option" key={kind}>
                    <span className="option-icon">
                      <Icon size={27} />
                    </span>
                    <div className="eyebrow">{tag}</div>
                    <h2>{title}</h2>
                    <p>{text}</p>
                    {kind === 'custom' && !native && (
                      <label>
                        Demo folder path
                        <input
                          value={custom}
                          onChange={(e) => setCustom(e.target.value)}
                          placeholder="C:\\Users\\You\\Downloads"
                        />
                      </label>
                    )}
                    <button
                      className={`button ${kind === 'quick' ? 'primary' : 'secondary'}`}
                      disabled={busy || scanActive || offline}
                      onClick={() => void start(kind)}
                    >
                      {kind === 'custom' ? 'Choose folders' : 'Start scan'}
                      <ArrowRight size={16} />
                    </button>
                  </section>
                ))}
              </div>
              {status?.scan && <ScanCard scan={status.scan} act={act} busy={busy} />}
              <div className="banner">
                <CircleHelp size={19} />
                Quick scan checks executable files on disk. Process memory, archives, locked files,
                and kernel execution blocking are outside this release’s coverage.
              </div>
            </>
          )}
          {page === 'Quarantine' && (
            <section className="panel">
              {!status?.quarantine.length ? (
                <Empty icon={<ShieldCheck size={42} />} heading="Nothing in quarantine">
                  When you quarantine a detected file, an encrypted backup and its report appear
                  here.
                </Empty>
              ) : (
                <div className="records">
                  {status.quarantine.map((entry) => (
                    <article className="record" key={entry.id}>
                      <div>
                        <span className={`subtle-tag ${entry.source_removed ? '' : 'danger'}`}>
                          {entry.restored_at
                            ? 'RESTORED BACKUP'
                            : entry.source_removed
                              ? 'ISOLATED'
                              : 'INCOMPLETE — REVIEW'}
                        </span>
                        <h3>{entry.threat.findings[0]?.name ?? 'Detected file'}</h3>
                        <p className="file-path">{entry.threat.path}</p>
                        <small>
                          {formatDate(entry.quarantined_at)} · {bytes(entry.threat.size)}
                        </small>
                        {entry.staging_path && (
                          <p className="file-path">Staged file: {entry.staging_path}</p>
                        )}
                      </div>
                      <div className="record-actions">
                        <button
                          className="button secondary"
                          onClick={() => setDetail(entry.threat)}
                        >
                          Report
                        </button>
                        <button
                          className="button secondary"
                          disabled={busy || !native || !!entry.staging_path}
                          onClick={() => void restore(entry.id, entry.threat.path)}
                        >
                          Restore
                        </button>
                        <button
                          className="button danger-button"
                          disabled={busy || !!entry.staging_path}
                          onClick={() => {
                            if (
                              window.confirm(
                                'Permanently delete this encrypted quarantine backup? This cannot be undone.',
                              )
                            )
                              void act({ action: 'delete_quarantine', id: entry.id });
                          }}
                        >
                          Delete backup
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
              )}
            </section>
          )}
          {page === 'Settings' && status && (
            <Settings
              config={status.config}
              act={act}
              busy={busy || offline}
              theme={theme}
              setTheme={setTheme}
            />
          )}
          {page === 'History' && (
            <>
              <section className="panel">
                <div className="panel-heading">
                  <h3>Scan reports</h3>
                  <span className="subtle-tag">LAST 100 SCANS</span>
                </div>
                {status?.history.length ? (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>Scan</th>
                          <th>Completed</th>
                          <th>Files checked</th>
                          <th>Skipped / errors</th>
                          <th>Findings</th>
                          <th>Result</th>
                        </tr>
                      </thead>
                      <tbody>
                        {status.history.map((scan) => (
                          <tr key={scan.id}>
                            <td className="capitalize">{scan.kind} scan</td>
                            <td>{formatDate(scan.finished_at)}</td>
                            <td>{count(scan.scanned)}</td>
                            <td>
                              {scan.skipped} / {scan.errors}
                            </td>
                            <td>{scan.threats}</td>
                            <td>
                              <span className="subtle-tag">{scan.state}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty icon={<History size={36} />} heading="A fresh start">
                    Your scan history will appear here after your first scan.
                  </Empty>
                )}
              </section>
              <section className="panel history-activity">
                <div className="panel-heading">
                  <h3>Service activity</h3>
                  <span className="subtle-tag">CURRENT SESSION</span>
                </div>
                {status?.activity.map((a, i) => (
                  <div className="log-row" key={i}>
                    <time>{formatDate(a.at)}</time>
                    <span className={a.level === 'error' ? 'danger' : ''}>{a.message}</span>
                  </div>
                ))}
              </section>
            </>
          )}
          <footer className="app-footer">
            <span>
              <LockKeyhole size={12} /> Your files never leave this device.
            </span>
            <span>Unbreakable Protection. Zero Cost. Built in Rust.</span>
          </footer>
        </main>
      </div>
      <dialog ref={detailDialog} className="threat-dialog" onClose={() => setDetail(null)}>
        {detail && (
          <>
            <div className="panel-heading">
              <h2>Detection report</h2>
              <button
                className="icon-button"
                aria-label="Close report"
                onClick={() => detailDialog.current?.close()}
              >
                <X />
              </button>
            </div>
            <dl>
              <dt>File</dt>
              <dd>{detail.path}</dd>
              <dt>SHA-256</dt>
              <dd className="hash">{detail.sha256}</dd>
              <dt>Detected</dt>
              <dd>{formatDate(detail.detected_at)}</dd>
              <dt>Status</dt>
              <dd>{detail.status}</dd>
            </dl>
            {detail.findings.map((f, i) => (
              <div className="finding" key={i}>
                <span className="subtle-tag danger">
                  {f.severity} · {f.method}
                </span>
                <h3>{f.name}</h3>
                <p>{f.explanation}</p>
              </div>
            ))}
            <p className="muted-copy">
              A detection is a signal to review. Heuristics can match legitimate software.
            </p>
          </>
        )}
      </dialog>
    </div>
  );
}

function Stat({
  icon,
  label,
  value,
  note,
  compact,
  warning,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  note: string;
  compact?: boolean;
  warning?: boolean;
}) {
  return (
    <section className={`panel stat ${warning ? 'warning-stat' : ''}`}>
      <div className="stat-label">
        {label}
        <span>{icon}</span>
      </div>
      <strong className={compact ? 'compact-value' : ''}>{value}</strong>
      <p>
        <span className="tiny-dot" />
        {note}
      </p>
    </section>
  );
}
function Layer({
  icon,
  title,
  description,
  enabled,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  enabled: boolean;
}) {
  return (
    <div className="layer">
      <span className="layer-icon">{icon}</span>
      <div>
        <h4>{title}</h4>
        <p>{description}</p>
      </div>
      <span className={`layer-status ${enabled ? 'enabled' : ''}`}>
        {enabled ? <CheckCheck size={16} /> : <Pause size={14} />}
      </span>
    </div>
  );
}
function ScanCard({
  scan,
  act,
  busy,
}: {
  scan: NonNullable<Status['scan']>;
  act: (a: Action) => Promise<void>;
  busy: boolean;
}) {
  const active = ['running', 'paused', 'enumerating'].includes(scan.state);
  const done = scan.scanned + scan.skipped;
  return (
    <section className="panel scan-progress" aria-live="polite">
      <div className="panel-heading">
        <h3>
          <Search size={18} />
          <span className="capitalize">{scan.kind} scan</span>
          <span className="subtle-tag">{scan.state}</span>
        </h3>
        <span>{count(scan.scanned)} files checked</span>
      </div>
      <progress
        value={done}
        max={Math.max(scan.total_files ?? done + 1, 1)}
        aria-label="Scan progress"
      />
      <div className="progress-info">
        <p className="file-path">
          {scan.current_path ??
            `${scan.threats} findings · ${scan.skipped} skipped · ${scan.errors} read errors`}
        </p>
        <span>
          {!active
            ? 'Scan finished'
            : scan.estimated_remaining_seconds === null
              ? 'Estimating time…'
              : `About ${scan.estimated_remaining_seconds}s remaining`}
        </span>
      </div>
      {active && (
        <div className="record-actions">
          <button
            className="button secondary"
            disabled={busy}
            onClick={() =>
              void act({ action: scan.state === 'paused' ? 'resume_scan' : 'pause_scan' })
            }
          >
            {scan.state === 'paused' ? <Play size={15} /> : <Pause size={15} />}{' '}
            {scan.state === 'paused' ? 'Resume' : 'Pause'}
          </button>
          <button
            className="button secondary"
            disabled={busy}
            onClick={() => void act({ action: 'cancel_scan' })}
          >
            <X size={15} />
            Cancel scan
          </button>
        </div>
      )}
    </section>
  );
}
function ThreatList({
  threats,
  detail,
  act,
  busy,
}: {
  threats: Threat[];
  detail: (t: Threat) => void;
  act: (a: Action) => Promise<void>;
  busy: boolean;
}) {
  return (
    <section className="panel threat-list">
      <div className="panel-heading">
        <h3>Potential threats to review</h3>
        <span className="subtle-tag danger">{threats.length} PENDING</span>
      </div>
      {threats.map((t) => (
        <article className="record" key={t.id}>
          <div>
            <h3>{t.findings[0]?.name}</h3>
            <p className="file-path">{t.path}</p>
            <small>{t.findings.map((f) => f.method).join(' + ')}</small>
          </div>
          <div className="record-actions">
            <button className="button secondary" onClick={() => detail(t)}>
              Details
            </button>
            <button
              className="button secondary"
              disabled={busy}
              onClick={() => {
                if (
                  window.confirm(
                    'Allow this exact file hash? Future copies with the same hash will be skipped.',
                  )
                )
                  void act({ action: 'allow', id: t.id });
              }}
            >
              Allow hash
            </button>
            <button
              className="button danger-button"
              disabled={busy}
              onClick={() => void act({ action: 'quarantine', id: t.id })}
            >
              Quarantine
            </button>
          </div>
        </article>
      ))}
    </section>
  );
}

function Settings({
  config,
  act,
  busy,
  theme,
  setTheme,
}: {
  config: Config;
  act: (a: Action) => Promise<void>;
  busy: boolean;
  theme: string;
  setTheme: (t: string) => void;
}) {
  const [draft, setDraft] = useState(config);
  const [roots, setRoots] = useState(config.watch_paths.join('\n'));
  const [exclusions, setExclusions] = useState(config.exclusions.join('\n'));
  const [feed, setFeed] = useState(config.update_manifest_url ?? '');
  const [key, setKey] = useState(config.update_public_key ?? '');
  const paths = (text: string) =>
    text
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void act({
      action: 'save_config',
      config: {
        ...draft,
        watch_paths: paths(roots),
        exclusions: paths(exclusions),
        update_manifest_url: feed.trim() || null,
        update_public_key: key.trim() || null,
      },
    });
  };
  return (
    <form onSubmit={submit} className="settings-form">
      <section className="panel settings-panel">
        <div className="panel-heading">
          <h3>Protection preferences</h3>
          <ShieldCheck size={18} />
        </div>
        <div className="setting-row">
          <div>
            <h4>File monitoring</h4>
            <p>Watch selected folders for created and modified files.</p>
          </div>
          <Toggle
            label="File monitoring"
            checked={draft.protection_enabled}
            onChange={(v) => setDraft({ ...draft, protection_enabled: v })}
          />
        </div>
        <div className="setting-row">
          <div>
            <h4>Heuristic analysis</h4>
            <p>Review signals for suspicious script combinations. No automatic deletion.</p>
          </div>
          <Toggle
            label="Heuristic analysis"
            checked={draft.heuristics_enabled}
            onChange={(v) => setDraft({ ...draft, heuristics_enabled: v })}
          />
        </div>
        <div className="setting-row">
          <div>
            <h4>Cloud lookup</h4>
            <p>Local scanning only. No cloud provider is included in this release.</p>
          </div>
          <span className="subtle-tag">OFF · LOCAL ONLY</span>
        </div>
        <label>
          Monitored folders <small>One existing absolute path per line</small>
          <textarea value={roots} onChange={(e) => setRoots(e.target.value)} rows={3} />
        </label>
        <label>
          Excluded folders or files <small>Exclusions reduce scan coverage</small>
          <textarea value={exclusions} onChange={(e) => setExclusions(e.target.value)} rows={3} />
        </label>
        <label>
          Maximum file size
          <select
            value={draft.max_file_bytes}
            onChange={(e) => setDraft({ ...draft, max_file_bytes: Number(e.target.value) })}
          >
            {[16, 32, 64, 128, 256].map((n) => (
              <option key={n} value={n * 1024 * 1024}>
                {n} MiB
              </option>
            ))}
          </select>
        </label>
      </section>
      <section className="panel settings-panel">
        <div className="panel-heading">
          <h3>Schedules & signatures</h3>
          <Clock3 size={18} />
        </div>
        <label>
          Quick scan schedule
          <select
            value={draft.scan_interval_hours ?? 0}
            onChange={(e) =>
              setDraft({ ...draft, scan_interval_hours: Number(e.target.value) || null })
            }
          >
            <option value={0}>Manual scans only</option>
            <option value={24}>Every 24 hours while service runs</option>
            <option value={168}>Every 7 days while service runs</option>
          </select>
        </label>
        <label>
          Signed update feed{' '}
          <input
            type="url"
            value={feed}
            placeholder="https://your-feed.example/signatures.signed.json"
            onChange={(e) => setFeed(e.target.value)}
          />
        </label>
        <label>
          Trusted Ed25519 public key{' '}
          <input
            value={key}
            placeholder="64 lowercase hexadecimal characters"
            onChange={(e) => setKey(e.target.value)}
          />
        </label>
        <label>
          Update schedule
          <select
            value={draft.update_interval_hours ?? 0}
            onChange={(e) =>
              setDraft({ ...draft, update_interval_hours: Number(e.target.value) || null })
            }
          >
            <option value={0}>Manual updates only</option>
            <option value={24}>Every 24 hours while service runs</option>
            <option value={168}>Every 7 days while service runs</option>
          </select>
        </label>
        <button
          type="button"
          className="button secondary"
          disabled={busy || !config.update_manifest_url}
          onClick={() => void act({ action: 'update_signatures' })}
        >
          <ArrowDownToLine size={16} />
          Check signed feed
        </button>
        <p className="muted-copy">
          Save feed settings before checking. Update checks disclose your IP address to your chosen
          host; file hashes and contents are never sent.
        </p>
      </section>
      <section className="panel settings-panel">
        <div className="panel-heading">
          <h3>Whitelist & appearance</h3>
          <Settings2 size={18} />
        </div>
        {draft.allowed_hashes.length ? (
          draft.allowed_hashes.map((hash) => (
            <div className="whitelist-item" key={hash}>
              <code>{hash}</code>
              <button
                className="icon-button"
                type="button"
                aria-label={`Remove allowed hash ${hash}`}
                onClick={() =>
                  setDraft({
                    ...draft,
                    allowed_hashes: draft.allowed_hashes.filter((h) => h !== hash),
                  })
                }
              >
                <X size={16} />
              </button>
            </div>
          ))
        ) : (
          <p className="muted-copy">
            No hashes allowed. You can whitelist an exact hash from a detection report.
          </p>
        )}
        <div className="setting-row">
          <div>
            <h4>Light appearance</h4>
            <p>Same calm interface, a brighter canvas.</p>
          </div>
          <Toggle
            label="Light appearance"
            checked={theme === 'light'}
            onChange={(v) => setTheme(v ? 'light' : 'dark')}
          />
        </div>
      </section>
      <div className="settings-actions">
        <p>Settings and history are stored on this device.</p>
        <button className="button primary" disabled={busy} type="submit">
          <Check size={16} />
          Save preferences
        </button>
      </div>
    </form>
  );
}
