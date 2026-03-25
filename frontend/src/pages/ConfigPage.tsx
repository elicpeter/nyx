import { useState, useCallback } from 'react';
import {
  useConfig,
  useSources,
  useSinks,
  useSanitizers,
  useTerminators,
  useProfiles,
} from '../api/queries/config';
import {
  useAddSource,
  useDeleteSource,
  useAddSink,
  useDeleteSink,
  useAddSanitizer,
  useDeleteSanitizer,
  useAddTerminator,
  useDeleteTerminator,
  useAddProfile,
  useDeleteProfile,
  useActivateProfile,
  useToggleTriageSync,
} from '../api/mutations/config';
import { LoadingState } from '../components/ui/LoadingState';
import { ErrorState } from '../components/ui/ErrorState';
import type { LabelEntryView, TerminatorView, ProfileView } from '../api/types';

const LANG_OPTIONS = [
  'javascript',
  'typescript',
  'python',
  'go',
  'java',
  'c',
  'cpp',
  'php',
  'ruby',
  'rust',
];

const CAP_OPTIONS = [
  'all',
  'env_var',
  'html_escape',
  'shell_escape',
  'url_encode',
  'json_parse',
  'file_io',
  'sql_query',
  'deserialize',
  'ssrf',
  'code_exec',
  'crypto',
];

// ── Collapsible Config Section ───────────────────────────────────────────────

function ConfigSection({
  title,
  id,
  children,
}: {
  title: string;
  id: string;
  children: React.ReactNode;
}) {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="config-section" id={id}>
      <div
        className={`config-section-header${collapsed ? ' collapsed' : ''}`}
        onClick={() => setCollapsed(!collapsed)}
      >
        <span
          className={`config-collapse-arrow${collapsed ? ' collapsed' : ''}`}
        >
          &#9660;
        </span>{' '}
        <strong>{title}</strong>
      </div>
      <div className={`config-section-body${collapsed ? ' collapsed' : ''}`}>
        {children}
      </div>
    </div>
  );
}

// ── Label Table (Source/Sink/Sanitizer) ──────────────────────────────────────

function LabelSection({
  title,
  id,
  kind,
  entries,
  onAdd,
  onDelete,
}: {
  title: string;
  id: string;
  kind: string;
  entries: LabelEntryView[];
  onAdd: (body: { lang: string; matchers: string[]; cap: string }) => void;
  onDelete: (entry: LabelEntryView) => void;
}) {
  const [lang, setLang] = useState('');
  const [matcher, setMatcher] = useState('');
  const [cap, setCap] = useState('all');

  const builtins = entries.filter((e) => e.is_builtin);
  const custom = entries.filter((e) => !e.is_builtin);

  const handleAdd = useCallback(() => {
    if (!lang || !matcher) return;
    onAdd({ lang, matchers: [matcher], cap });
    setMatcher('');
  }, [lang, matcher, cap, onAdd]);

  return (
    <ConfigSection title={title} id={id}>
      <div className="inline-form add-label-form">
        <div className="form-group">
          <label>Language</label>
          <select
            style={{ width: 140 }}
            value={lang}
            onChange={(e) => setLang(e.target.value)}
          >
            <option value="">Select...</option>
            {LANG_OPTIONS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label>Matcher</label>
          <input
            type="text"
            placeholder="functionName"
            value={matcher}
            onChange={(e) => setMatcher(e.target.value)}
          />
        </div>
        <div className="form-group">
          <label>Capability</label>
          <select value={cap} onChange={(e) => setCap(e.target.value)}>
            {CAP_OPTIONS.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <button className="btn btn-primary btn-sm" onClick={handleAdd}>
          Add {kind}
        </button>
      </div>
      <div className="table-wrap" style={{ marginTop: 8 }}>
        {entries.length === 0 ? (
          <div className="empty-state" style={{ padding: 12 }}>
            <p>No {kind} rules</p>
          </div>
        ) : (
          <table className="label-table">
            <thead>
              <tr>
                <th>Language</th>
                <th>Matchers</th>
                <th>Cap</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {builtins.map((e, i) => (
                <tr key={`b-${i}`} className="label-builtin">
                  <td>{e.lang}</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>
                    {e.matchers.join(', ')}
                  </td>
                  <td>{e.cap}</td>
                  <td>
                    <span className="badge-builtin">built-in</span>
                  </td>
                </tr>
              ))}
              {custom.map((e, i) => (
                <tr key={`c-${i}`}>
                  <td>{e.lang}</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>
                    {e.matchers.join(', ')}
                  </td>
                  <td>{e.cap}</td>
                  <td>
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => onDelete(e)}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </ConfigSection>
  );
}

// ── Config Page ──────────────────────────────────────────────────────────────

export function ConfigPage() {
  const {
    data: config,
    isLoading: configLoading,
    error: configError,
  } = useConfig();
  const { data: sources } = useSources();
  const { data: sinks } = useSinks();
  const { data: sanitizers } = useSanitizers();
  const { data: terminators } = useTerminators();
  const { data: profiles } = useProfiles();

  const addSource = useAddSource();
  const deleteSource = useDeleteSource();
  const addSink = useAddSink();
  const deleteSink = useDeleteSink();
  const addSanitizer = useAddSanitizer();
  const deleteSanitizer = useDeleteSanitizer();
  const addTerminator = useAddTerminator();
  const deleteTerminator = useDeleteTerminator();
  const addProfile = useAddProfile();
  const deleteProfile = useDeleteProfile();
  const activateProfile = useActivateProfile();
  const toggleTriageSync = useToggleTriageSync();

  const [termLang, setTermLang] = useState('');
  const [termName, setTermName] = useState('');
  const [profileName, setProfileName] = useState('');

  const handleAddTerminator = useCallback(() => {
    if (!termLang || !termName) return;
    addTerminator.mutate({ lang: termLang, name: termName });
    setTermName('');
  }, [termLang, termName, addTerminator]);

  const handleSaveProfile = useCallback(() => {
    if (!profileName) return;
    addProfile.mutate({ name: profileName, settings: {} });
    setProfileName('');
  }, [profileName, addProfile]);

  if (configLoading) return <LoadingState message="Loading configuration..." />;
  if (configError) return <ErrorState message={configError.message} />;

  // Extract config fields (config is typed as unknown since it's the raw NyxConfig)
  const cfg = config as Record<string, Record<string, unknown>> | undefined;
  const scanner = cfg?.scanner as Record<string, unknown> | undefined;
  const output = cfg?.output as Record<string, unknown> | undefined;
  const server = cfg?.server as Record<string, unknown> | undefined;

  return (
    <>
      <div className="page-header">
        <h2>Config</h2>
      </div>

      {/* General Section */}
      <ConfigSection title="General" id="config-general">
        <div className="detail-meta">
          <div>
            <strong>Analysis Mode:</strong> {String(scanner?.mode || 'full')}
          </div>
          <div>
            <strong>Min Severity:</strong>{' '}
            {String(scanner?.min_severity || 'Low')}
          </div>
          <div>
            <strong>Max File Size:</strong>{' '}
            {scanner?.max_file_size_mb
              ? String(scanner.max_file_size_mb) + ' MB'
              : 'unlimited'}
          </div>
          <div>
            <strong>Excluded Dirs:</strong>{' '}
            {((scanner?.excluded_directories as string[]) || []).join(', ')}
          </div>
          <div>
            <strong>Excluded Exts:</strong>{' '}
            {((scanner?.excluded_extensions as string[]) || []).join(', ')}
          </div>
          <div>
            <strong>Attack Surface Ranking:</strong>{' '}
            {output?.attack_surface_ranking ? 'Enabled' : 'Disabled'}
          </div>
        </div>
        <div
          style={{
            marginTop: 'var(--space-4)',
            paddingTop: 'var(--space-3)',
            borderTop: '1px solid var(--border)',
          }}
        >
          <div className="toggle-inline">
            <input
              type="checkbox"
              id="triage-sync-toggle"
              checked={!!server?.triage_sync}
              onChange={(e) =>
                toggleTriageSync.mutate({ enabled: e.target.checked })
              }
            />
            <label htmlFor="triage-sync-toggle">
              <strong>Triage Sync</strong> &mdash; Auto-sync triage decisions to{' '}
              <code>.nyx/triage.json</code> for git-based team sharing
            </label>
          </div>
        </div>
      </ConfigSection>

      {/* Sources */}
      <LabelSection
        title="Custom Sources"
        id="config-sources"
        kind="source"
        entries={sources || []}
        onAdd={(body) => addSource.mutate(body)}
        onDelete={(e) =>
          deleteSource.mutate({
            lang: e.lang,
            matchers: e.matchers,
            cap: e.cap,
          })
        }
      />

      {/* Sinks */}
      <LabelSection
        title="Custom Sinks"
        id="config-sinks"
        kind="sink"
        entries={sinks || []}
        onAdd={(body) => addSink.mutate(body)}
        onDelete={(e) =>
          deleteSink.mutate({ lang: e.lang, matchers: e.matchers, cap: e.cap })
        }
      />

      {/* Sanitizers */}
      <LabelSection
        title="Custom Sanitizers"
        id="config-sanitizers"
        kind="sanitizer"
        entries={sanitizers || []}
        onAdd={(body) => addSanitizer.mutate(body)}
        onDelete={(e) =>
          deleteSanitizer.mutate({
            lang: e.lang,
            matchers: e.matchers,
            cap: e.cap,
          })
        }
      />

      {/* Terminators */}
      <ConfigSection title="Terminators" id="config-terminators">
        <div className="inline-form" id="add-term-form">
          <div className="form-group">
            <label>Language</label>
            <select
              style={{ width: 140 }}
              value={termLang}
              onChange={(e) => setTermLang(e.target.value)}
            >
              <option value="">Select...</option>
              {LANG_OPTIONS.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label>Function Name</label>
            <input
              type="text"
              placeholder="process.exit"
              value={termName}
              onChange={(e) => setTermName(e.target.value)}
            />
          </div>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleAddTerminator}
          >
            Add Terminator
          </button>
        </div>
        <div className="table-wrap">
          {!terminators || terminators.length === 0 ? (
            <div className="empty-state" style={{ padding: 12 }}>
              <p>No terminators configured</p>
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Language</th>
                  <th>Name</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {(terminators as TerminatorView[]).map((t, i) => (
                  <tr key={i}>
                    <td>{t.lang}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{t.name}</td>
                    <td>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => deleteTerminator.mutate(t)}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </ConfigSection>

      {/* Profiles */}
      <ConfigSection title="Profiles" id="config-profiles">
        <div className="table-wrap">
          {!profiles || profiles.length === 0 ? (
            <div className="empty-state" style={{ padding: 12 }}>
              <p>No profiles configured</p>
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Settings</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {(profiles as ProfileView[]).map((p) => (
                  <tr key={p.name}>
                    <td>
                      <strong>{p.name}</strong>
                    </td>
                    <td>
                      {p.is_builtin ? (
                        <span className="badge-builtin">built-in</span>
                      ) : (
                        <span className="badge-custom">custom</span>
                      )}
                    </td>
                    <td
                      style={{
                        fontSize: 'var(--text-xs)',
                        maxWidth: 300,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                    >
                      {JSON.stringify(p.settings)}
                    </td>
                    <td>
                      <button
                        className="btn btn-sm"
                        onClick={() => activateProfile.mutate(p.name)}
                      >
                        Activate
                      </button>
                      {!p.is_builtin && (
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => deleteProfile.mutate(p.name)}
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        <div className="inline-form" style={{ marginTop: 12 }}>
          <div className="form-group">
            <label>Profile Name</label>
            <input
              type="text"
              placeholder="my_profile"
              value={profileName}
              onChange={(e) => setProfileName(e.target.value)}
            />
          </div>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleSaveProfile}
          >
            Save Current as Profile
          </button>
        </div>
      </ConfigSection>
    </>
  );
}
