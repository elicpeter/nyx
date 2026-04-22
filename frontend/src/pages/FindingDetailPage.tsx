import { useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useFinding } from '../api/queries/findings';
import { useBulkTriage } from '../api/mutations/triage';
import { truncPath } from '../utils/truncPath';
import { escapeHtml, highlightSyntax } from '../utils/syntaxHighlight';
import { parseNoteText } from '../utils/parseNote';
import { findingToMarkdown } from '../utils/findingMarkdown';
import { CopyMarkdownButton } from '../components/CopyMarkdownButton';
import { CodeViewerModal } from '../modals/CodeViewerModal';
import type {
  FindingView,
  Evidence,
  FlowStep,
  SpanEvidence,
  RelatedFindingView,
} from '../api/types';

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatTriageState(state: string): string {
  return (state || 'open').replace(/_/g, ' ');
}

const TRIAGE_STATES = [
  'open',
  'investigating',
  'false_positive',
  'accepted_risk',
  'suppressed',
  'fixed',
] as const;

function isStateFinding(f: FindingView): boolean {
  return f.rule_id.startsWith('state-');
}

const STATE_REMEDIATION_HINTS: Record<string, string> = {
  'state-use-after-close':
    'Ensure the resource is not accessed after calling close/free. Consider restructuring to use the resource before releasing it.',
  'state-double-close':
    'Remove the duplicate close call, or guard with a null/closed check.',
  'state-resource-leak':
    'Add a close/free call before the function exits, or use a language-specific cleanup pattern (defer, with, try-with-resources, RAII).',
  'state-resource-leak-possible':
    'Ensure the resource is closed on all code paths, including error/early-return paths.',
  'state-unauthed-access':
    'Add an authentication check before this operation, or move it behind an auth middleware/guard.',
};

const STATE_RULE_DESCRIPTIONS: Record<string, string> = {
  'state-use-after-close': 'Variable used after its resource handle was closed',
  'state-double-close': 'Resource handle closed more than once',
  'state-resource-leak': 'Resource acquired but never closed',
  'state-resource-leak-possible': 'Resource may not be closed on all paths',
  'state-unauthed-access': 'Sensitive operation reached without authentication',
};

// ── Collapsible Section ─────────────────────────────────────────────────────

interface CollapsibleSectionProps {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

function CollapsibleSection({
  title,
  defaultOpen = true,
  children,
}: CollapsibleSectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="detail-section">
      <div className="section-toggle" onClick={() => setOpen((v) => !v)}>
        <span className={`toggle-arrow${!open ? ' collapsed' : ''}`}>
          &#9660;
        </span>{' '}
        {title}
      </div>
      <div className={`section-body${!open ? ' collapsed' : ''}`}>
        {children}
      </div>
    </div>
  );
}

// ── Evidence Cards ──────────────────────────────────────────────────────────

function EvidenceCard({
  kind,
  color,
  span,
}: {
  kind: string;
  color: string;
  span: SpanEvidence;
}) {
  return (
    <div className="evidence-card">
      <div className="evidence-kind" style={{ color }}>
        {kind}
      </div>
      <div>
        {span.path}:{span.line}:{span.col}
      </div>
      {span.snippet && <div className="evidence-snippet">{span.snippet}</div>}
    </div>
  );
}

function StateTransitionCard({
  evidence,
  ruleId,
}: {
  evidence: Evidence;
  ruleId: string;
}) {
  const st = evidence.state;
  if (!st) return null;

  const isAuth = st.machine === 'auth';
  const machineLabel = isAuth ? 'Authentication State' : 'Resource Lifecycle';
  const acquireLocation =
    ruleId.includes('leak') && evidence.sink
      ? `${evidence.sink.path}:${evidence.sink.line}:${evidence.sink.col}`
      : null;

  return (
    <div className="state-transition-card">
      <div className="state-machine-label">{machineLabel}</div>
      {st.subject && (
        <div className="state-subject">
          <span className="state-subject-label">Variable:</span>
          <code className="state-subject-name">{st.subject}</code>
        </div>
      )}
      <div className="state-transition-visual">
        <span className="state-from">{st.from_state}</span>
        <span className="state-arrow">&rarr;</span>
        <span className="state-to">{st.to_state}</span>
      </div>
      {acquireLocation && (
        <div className="state-acquire-location">
          Acquired at: {acquireLocation}
        </div>
      )}
    </div>
  );
}

function StateRemediationHint({ ruleId }: { ruleId: string }) {
  const hint = STATE_REMEDIATION_HINTS[ruleId];
  if (!hint) return null;

  return (
    <div className="state-remediation">
      <div className="state-remediation-label">Remediation</div>
      {hint}
    </div>
  );
}

function EvidenceSection({
  evidence,
  skipStateCard,
}: {
  evidence: Evidence;
  skipStateCard?: boolean;
}) {
  const cards: React.ReactNode[] = [];

  if (evidence.source) {
    cards.push(
      <EvidenceCard
        key="source"
        kind="Source"
        color="var(--success)"
        span={evidence.source}
      />,
    );
  }

  if (evidence.sink) {
    cards.push(
      <EvidenceCard
        key="sink"
        kind="Sink"
        color="var(--sev-high)"
        span={evidence.sink}
      />,
    );
  }

  for (let i = 0; i < (evidence.guards?.length ?? 0); i++) {
    cards.push(
      <EvidenceCard
        key={`guard-${i}`}
        kind="Guard"
        color="var(--accent)"
        span={evidence.guards[i]}
      />,
    );
  }

  for (let i = 0; i < (evidence.sanitizers?.length ?? 0); i++) {
    cards.push(
      <EvidenceCard
        key={`sanitizer-${i}`}
        kind="Sanitizer"
        color="var(--sev-medium)"
        span={evidence.sanitizers[i]}
      />,
    );
  }

  if (evidence.state && !skipStateCard) {
    const st = evidence.state;
    cards.push(
      <div className="evidence-card" key="state">
        <div className="evidence-kind">State: {st.machine}</div>
        <div>
          {st.subject ? `${st.subject}: ` : ''}
          {st.from_state} &rarr; {st.to_state}
        </div>
      </div>,
    );
  }

  if (cards.length === 0) return null;
  return <>{cards}</>;
}

// ── Notes Section ───────────────────────────────────────────────────────────

function NotesSection({ evidence }: { evidence: Evidence }) {
  if (!evidence.notes || evidence.notes.length === 0) return null;

  return (
    <ul style={{ listStyle: 'disc', paddingLeft: 20, margin: 0 }}>
      {evidence.notes.map((note, i) => (
        <li key={i} className="evidence-note">
          {parseNoteText(note)}
        </li>
      ))}
    </ul>
  );
}

// ── Confidence Section ──────────────────────────────────────────────────────

function ConfidenceSection({ finding }: { finding: FindingView }) {
  if (!finding.confidence) return null;

  const limiters = finding.evidence?.confidence_limiters;
  const showLimiters =
    limiters && limiters.length > 0 && finding.confidence !== 'High';

  return (
    <>
      <span className={`badge badge-conf-${finding.confidence.toLowerCase()}`}>
        {finding.confidence}
      </span>
      {finding.rank_score != null && (
        <span
          style={{
            marginLeft: 'var(--space-2)',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)',
          }}
        >
          Score: {finding.rank_score.toFixed(1)}
        </span>
      )}
      {finding.rank_reason && finding.rank_reason.length > 0 && (
        <div style={{ marginTop: 'var(--space-2)' }}>
          {finding.rank_reason.map(([k, v], i) => (
            <div key={i} className="evidence-note">
              <strong>{k}:</strong> {v}
            </div>
          ))}
        </div>
      )}
      {showLimiters && (
        <div style={{ marginTop: 'var(--space-3)' }}>
          <strong
            style={{
              fontSize: 'var(--text-sm)',
              color: 'var(--text-secondary)',
            }}
          >
            Why not higher confidence?
          </strong>
          <ul className="confidence-limiters">
            {limiters!.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

// ── Taint Flow Timeline ─────────────────────────────────────────────────────

const FLOW_KIND_COLORS: Record<string, string> = {
  source: 'var(--success)',
  assignment: 'var(--accent)',
  call: 'var(--sev-medium)',
  phi: 'var(--text-tertiary)',
  sink: 'var(--sev-high)',
};

const FLOW_KIND_LABELS: Record<string, string> = {
  source: 'Source',
  assignment: 'Assign',
  call: 'Call',
  phi: 'Phi',
  sink: 'Sink',
};

function FlowTimeline({ steps }: { steps: FlowStep[] }) {
  const [activeIdx, setActiveIdx] = useState<number | null>(null);

  if (steps.length === 0) return null;

  return (
    <div className="flow-timeline">
      {steps.map((s, i) => {
        const color = FLOW_KIND_COLORS[s.kind] || 'var(--text-secondary)';
        const label = FLOW_KIND_LABELS[s.kind] || s.kind;
        const isLast = i === steps.length - 1;

        return (
          <div
            key={i}
            className={`flow-step${s.is_cross_file ? ' flow-step-cross-file' : ''}${activeIdx === i ? ' active' : ''}`}
            onClick={() => setActiveIdx(i)}
          >
            <div className="flow-step-connector">
              <div className="flow-step-dot" style={{ background: color }} />
              {!isLast && <div className="flow-step-line" />}
            </div>
            <div className="flow-step-card">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                  marginBottom: 2,
                }}
              >
                <span className="flow-step-badge" style={{ color }}>
                  {label}
                </span>
                <span
                  style={{
                    fontSize: 'var(--text-xs)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  #{s.step}
                </span>
                {s.variable && (
                  <span
                    style={{
                      fontSize: 'var(--text-sm)',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {s.variable}
                  </span>
                )}
                {s.callee && (
                  <span
                    style={{
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {s.callee}
                  </span>
                )}
              </div>
              <div
                style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--text-tertiary)',
                }}
              >
                {s.file}:{s.line}:{s.col}
                {s.function ? ` in ${s.function}` : ''}
              </div>
              {s.snippet && (
                <div className="flow-step-snippet">{s.snippet}</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Related Findings ────────────────────────────────────────────────────────

function RelatedFindings({ findings }: { findings: RelatedFindingView[] }) {
  const navigate = useNavigate();

  if (findings.length === 0) return null;

  return (
    <>
      {findings.map((r) => (
        <div
          key={r.index}
          className="related-row"
          onClick={() => navigate(`/findings/${r.index}`)}
        >
          <span className={`badge badge-${r.severity.toLowerCase()}`}>
            {r.severity.charAt(0)}
          </span>
          <span style={{ fontSize: 'var(--text-xs)' }}>{r.rule_id}</span>
          <span
            className="cell-path"
            style={{ fontSize: 'var(--text-xs)', maxWidth: 200 }}
          >
            {truncPath(r.path, 30)}:{r.line}
          </span>
        </div>
      ))}
    </>
  );
}

// ── Code Preview ────────────────────────────────────────────────────────────

function CodePreview({
  lines,
  startLine,
  highlightLine,
  language,
}: {
  lines: string[];
  startLine: number;
  highlightLine: number;
  language?: string;
}) {
  const lang = (language || '').toLowerCase();

  return (
    <div className="code-block">
      {lines.map((line, i) => {
        const lineNum = startLine + i;
        const isHighlight = lineNum === highlightLine;
        return (
          <div
            key={lineNum}
            className={`code-line${isHighlight ? ' highlight' : ''}`}
          >
            <span className="line-number">{lineNum}</span>
            <span
              className="line-content"
              dangerouslySetInnerHTML={{
                __html: highlightSyntax(escapeHtml(line), lang),
              }}
            />
          </div>
        );
      })}
    </div>
  );
}

// ── Triage Actions ──────────────────────────────────────────────────────────

function TriageActions({
  finding,
  onTriage,
  isPending,
}: {
  finding: FindingView;
  onTriage: (state: string, note: string) => void;
  isPending: boolean;
}) {
  const [pendingState, setPendingState] = useState<string | null>(null);
  const [note, setNote] = useState('');

  const currentState = finding.triage_state || 'open';
  const availableStates = TRIAGE_STATES.filter((s) => s !== currentState);

  const handleConfirm = () => {
    if (!pendingState) return;
    onTriage(pendingState, note.trim());
    setPendingState(null);
    setNote('');
  };

  const handleCancel = () => {
    setPendingState(null);
    setNote('');
  };

  return (
    <div className="triage-actions" data-fingerprint={finding.fingerprint}>
      {finding.triage_note && (
        <div className="triage-current-note">
          <strong>Note:</strong> {finding.triage_note}
        </div>
      )}
      <div className="triage-buttons">
        {availableStates.map((s) => (
          <button
            key={s}
            className={`btn btn-sm btn-triage btn-triage-${s}`}
            disabled={isPending}
            onClick={() => setPendingState(s)}
          >
            {formatTriageState(s)}
          </button>
        ))}
      </div>
      {pendingState && (
        <div className="triage-note-input">
          <textarea
            placeholder="Add a note (optional)..."
            rows={2}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            autoFocus
          />
          <div className="triage-note-actions">
            <button
              className="btn btn-sm btn-primary"
              disabled={isPending}
              onClick={handleConfirm}
            >
              Confirm
            </button>
            <button className="btn btn-sm" onClick={handleCancel}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────────────

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();

  const { data: finding, isLoading, isError, error } = useFinding(id ?? '');

  const bulkTriage = useBulkTriage();
  const [codeModalOpen, setCodeModalOpen] = useState(false);

  const handleTriage = useCallback(
    (state: string, note: string) => {
      if (!finding) return;
      bulkTriage.mutate({
        fingerprints: [finding.fingerprint],
        state,
        note,
      });
    },
    [finding, bulkTriage],
  );

  if (isLoading) {
    return <div className="loading">Loading finding...</div>;
  }

  if (isError || !finding) {
    const msg = error instanceof Error ? error.message : 'Unknown error';
    return (
      <div className="error-state">
        <h3>Finding not found</h3>
        <p>{msg}</p>
      </div>
    );
  }

  const f = finding;
  const evidence = f.evidence;
  const isState = isStateFinding(f);
  const hasWhySection =
    f.message ||
    (evidence && (evidence.source || evidence.sink || evidence.state));
  const hasEvidence =
    evidence &&
    (evidence.source ||
      evidence.sink ||
      (evidence.guards && evidence.guards.length > 0) ||
      (evidence.sanitizers && evidence.sanitizers.length > 0) ||
      evidence.state);
  const hasNotes = evidence && evidence.notes && evidence.notes.length > 0;
  const hasFlow =
    evidence && evidence.flow_steps && evidence.flow_steps.length > 0;
  const hasRelated = f.related_findings && f.related_findings.length > 0;
  const hasLabels = f.labels && f.labels.length > 0;
  const hasCode = !!f.code_context;

  const sanitizerBadge =
    f.sanitizer_status && !isState ? (
      <span className={`badge sanitizer-badge-${f.sanitizer_status}`}>
        {f.sanitizer_status === 'none'
          ? 'No sanitizers'
          : f.sanitizer_status === 'bypassed'
            ? 'Sanitizer bypassed'
            : 'Sanitized'}
      </span>
    ) : null;

  return (
    <div className="detail-panel">
      <div className="detail-title-row">
        <h2>{f.rule_id}</h2>
        <CopyMarkdownButton
          iconOnly
          title="Copy as markdown"
          getMarkdown={() => findingToMarkdown(f)}
        />
      </div>

      <div className="badge-row">
        <span className={`badge badge-${f.severity.toLowerCase()}`}>
          {f.severity}
        </span>
        {f.confidence && (
          <span className={`badge badge-conf-${f.confidence.toLowerCase()}`}>
            {f.confidence}
          </span>
        )}
        <span className="badge">{f.category}</span>
        <span className={`badge badge-triage-${f.triage_state || 'open'}`}>
          {formatTriageState(f.triage_state || 'open')}
        </span>
        {sanitizerBadge}
      </div>

      <a
        href="#"
        className="file-location"
        onClick={(e) => {
          e.preventDefault();
          setCodeModalOpen(true);
        }}
      >
        {f.path}:{f.line}:{f.col}
      </a>

      {/* Triage Actions */}
      <TriageActions
        finding={f}
        onTriage={handleTriage}
        isPending={bulkTriage.isPending}
      />

      {/* Why Nyx Reported This */}
      {hasWhySection && (
        <CollapsibleSection title="Why Nyx Reported This">
          {isState ? (
            <>
              {STATE_RULE_DESCRIPTIONS[f.rule_id] && (
                <p style={{ marginBottom: 'var(--space-3)', lineHeight: 1.5 }}>
                  {STATE_RULE_DESCRIPTIONS[f.rule_id]}
                </p>
              )}
              {f.message && (
                <p style={{ marginBottom: 'var(--space-3)' }}>{f.message}</p>
              )}
              {evidence && (
                <StateTransitionCard evidence={evidence} ruleId={f.rule_id} />
              )}
              <StateRemediationHint ruleId={f.rule_id} />
            </>
          ) : (
            <>
              {evidence?.explanation && (
                <p style={{ marginBottom: 'var(--space-3)', lineHeight: 1.5 }}>
                  {evidence.explanation}
                </p>
              )}
              {f.message && (
                <p style={{ marginBottom: 'var(--space-3)' }}>{f.message}</p>
              )}
              {evidence?.source && (
                <p className="evidence-note">
                  Tainted data flows from{' '}
                  <strong>{evidence.source.kind}</strong> at line{' '}
                  {evidence.source.line} to a dangerous operation.
                </p>
              )}
              {evidence?.sink && (
                <p className="evidence-note">
                  Sink at line {evidence.sink.line}
                  {evidence.sink.snippet ? (
                    <>
                      : <code>{evidence.sink.snippet}</code>
                    </>
                  ) : null}
                </p>
              )}
              {f.guard_kind && (
                <p className="evidence-note">Guard: {f.guard_kind}</p>
              )}
            </>
          )}
        </CollapsibleSection>
      )}

      {/* Taint Flow */}
      {hasFlow && (
        <CollapsibleSection title="Taint Flow">
          <FlowTimeline steps={evidence!.flow_steps} />
        </CollapsibleSection>
      )}

      {/* Evidence */}
      {hasEvidence && (
        <CollapsibleSection title="Evidence">
          <EvidenceSection evidence={evidence!} skipStateCard={isState} />
        </CollapsibleSection>
      )}

      {/* Analysis Notes */}
      {hasNotes && (
        <CollapsibleSection title="Analysis Notes">
          <NotesSection evidence={evidence!} />
        </CollapsibleSection>
      )}

      {/* Confidence Reasoning */}
      {f.confidence && (
        <CollapsibleSection title="Confidence Reasoning">
          <ConfidenceSection finding={f} />
        </CollapsibleSection>
      )}

      {/* Related Findings */}
      {hasRelated && (
        <CollapsibleSection title="Related Findings">
          <RelatedFindings findings={f.related_findings} />
        </CollapsibleSection>
      )}

      {/* Labels */}
      {hasLabels && (
        <CollapsibleSection title="Labels">
          <div className="label-list">
            {f.labels.map(([k, v], i) => (
              <span key={i} className="label-item">
                <span className="label-key">{k}:</span>{' '}
                <span className="label-value">{v}</span>
              </span>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Code Preview */}
      {hasCode && (
        <CollapsibleSection title="Code Preview">
          <CodePreview
            lines={f.code_context!.lines}
            startLine={f.code_context!.start_line}
            highlightLine={f.code_context!.highlight_line}
            language={f.language}
          />
        </CollapsibleSection>
      )}
      <CodeViewerModal
        open={codeModalOpen}
        onClose={() => setCodeModalOpen(false)}
        finding={f}
      />
    </div>
  );
}
