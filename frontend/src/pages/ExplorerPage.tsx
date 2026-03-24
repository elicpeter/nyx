import { useState, useEffect, useCallback } from 'react';
import { useExplorerTree, useExplorerSymbols, useExplorerFindings } from '../api/queries/explorer';
import { useFinding } from '../api/queries/findings';
import { FileTree } from '../components/data-display/FileTree';
import { CodeViewer } from '../components/data-display/CodeViewer';
import { LoadingState } from '../components/ui/LoadingState';
import { EmptyState } from '../components/ui/EmptyState';
import { ExplorerIcon } from '../components/icons/Icons';
import type { TreeEntry, FlowStep, FindingView } from '../api/types';

type ExplorerMode = 'tree' | 'symbols' | 'hotspots';

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

export function ExplorerPage() {
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const [loadedChildren, setLoadedChildren] = useState<Map<string, TreeEntry[]>>(new Map());
  const [explorerMode, setExplorerMode] = useState<ExplorerMode>('tree');
  const [highlightLine, setHighlightLine] = useState<number | undefined>();
  const [expandQueue, setExpandQueue] = useState<string | null>(null);
  const [selectedFindingIndex, setSelectedFindingIndex] = useState<number | null>(null);

  const { data: rootEntries, isLoading: treeLoading } = useExplorerTree();
  const { data: childEntries } = useExplorerTree(expandQueue || undefined);
  const { data: symbols } = useExplorerSymbols(selectedPath);
  const { data: findings } = useExplorerFindings(selectedPath);
  const { data: fullFinding } = useFinding(selectedFindingIndex ?? '');

  // When child entries arrive for an expanded directory, store them
  useEffect(() => {
    if (expandQueue && childEntries) {
      setLoadedChildren((prev) => {
        const next = new Map(prev);
        next.set(expandQueue, childEntries);
        return next;
      });
      setExpandQueue(null);
    }
  }, [expandQueue, childEntries]);

  const handleToggleExpand = useCallback(
    (path: string) => {
      setExpandedPaths((prev) => {
        const next = new Set(prev);
        if (next.has(path)) {
          next.delete(path);
        } else {
          next.add(path);
          if (!loadedChildren.has(path)) {
            setExpandQueue(path);
          }
        }
        return next;
      });
    },
    [loadedChildren],
  );

  const handleSelectFile = useCallback((path: string) => {
    setSelectedPath(path);
    setHighlightLine(undefined);
    setSelectedFindingIndex(null);
  }, []);

  const handleSelectFinding = useCallback((index: number, line: number) => {
    setSelectedFindingIndex(index);
    setHighlightLine(line);
  }, []);

  // Detect language from selected file
  const selectedEntry = findEntry(rootEntries, loadedChildren, selectedPath);
  const language = selectedEntry?.language || '';

  // Build hotspot list: all files sorted by finding_count desc
  const hotspotFiles = buildHotspotList(rootEntries, loadedChildren);

  // Severity breakdown for right panel
  const sevBreakdown = findings
    ? findings.reduce(
        (acc, f) => {
          const key = f.severity.toUpperCase();
          acc[key] = (acc[key] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      )
    : {};

  // Build highlights and flow lines from full finding evidence
  const evidence = fullFinding?.evidence;
  const flowSteps = evidence?.flow_steps;
  const hasFlow = flowSteps && flowSteps.length > 0;
  const hasStateEvidence = fullFinding?.rule_id.startsWith('state-') && evidence?.state;

  const codeHighlights = selectedFindingIndex != null && evidence
    ? {
        sourceLine: evidence.source?.line,
        sinkLine: evidence.sink?.line,
        findingLine: fullFinding?.line,
      }
    : undefined;

  const flowLineSet = new Set<number>();
  if (hasFlow) {
    for (const step of flowSteps) {
      if (step.line) flowLineSet.add(step.line);
    }
  }

  return (
    <div className="explorer-page">
      {/* Left panel */}
      <div className="explorer-left">
        <div className="explorer-left-header">
          <div className="explorer-mode-toggle">
            {(['tree', 'symbols', 'hotspots'] as ExplorerMode[]).map((mode) => (
              <button
                key={mode}
                className={`mode-btn${explorerMode === mode ? ' active' : ''}`}
                onClick={() => setExplorerMode(mode)}
              >
                {mode === 'tree' ? 'Files' : mode === 'symbols' ? 'Symbols' : 'Hotspots'}
              </button>
            ))}
          </div>
        </div>
        <div className="explorer-left-body">
          {explorerMode === 'tree' && (
            <>
              {treeLoading && <LoadingState message="Loading files..." />}
              {rootEntries && (
                <FileTree
                  entries={rootEntries}
                  expandedPaths={expandedPaths}
                  selectedPath={selectedPath}
                  onToggleExpand={handleToggleExpand}
                  onSelectFile={handleSelectFile}
                  loadedChildren={loadedChildren}
                />
              )}
            </>
          )}

          {explorerMode === 'symbols' && (
            <div className="explorer-symbol-list">
              {!selectedPath && (
                <div className="explorer-hint">Select a file to view symbols</div>
              )}
              {selectedPath && symbols && symbols.length === 0 && (
                <div className="explorer-hint">No symbols found</div>
              )}
              {symbols &&
                symbols.map((sym, i) => (
                  <div key={`${sym.name}-${i}`} className="explorer-symbol-item">
                    <span className={`symbol-kind symbol-kind-${sym.kind}`}>
                      {sym.kind === 'function' ? 'ƒ' : 'm'}
                    </span>
                    <span className="symbol-name">{sym.name}</span>
                    {sym.arity !== undefined && sym.arity !== null && (
                      <span className="symbol-arity">({sym.arity})</span>
                    )}
                    {sym.finding_count > 0 && (
                      <span className="tree-node-badge">{sym.finding_count}</span>
                    )}
                  </div>
                ))}
            </div>
          )}

          {explorerMode === 'hotspots' && (
            <div className="explorer-hotspot-list">
              {hotspotFiles.length === 0 && (
                <div className="explorer-hint">No findings in scanned files</div>
              )}
              {hotspotFiles.map((entry) => (
                <div
                  key={entry.path}
                  className={`hotspot-item${selectedPath === entry.path ? ' selected' : ''}`}
                  onClick={() => handleSelectFile(entry.path)}
                >
                  <span className="hotspot-name" title={entry.path}>
                    {entry.name}
                  </span>
                  <span className="hotspot-count">
                    <span
                      className={`badge badge-sev badge-sev-${(entry.severity_max || 'low').toLowerCase()}`}
                    >
                      {entry.finding_count}
                    </span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Center panel */}
      <div className="explorer-center">
        {selectedPath && (
          <div className="explorer-center-header">
            <span className="explorer-file-path">{selectedPath}</span>
          </div>
        )}
        <div className="explorer-center-body">
          {!selectedPath && (
            <EmptyState
              icon={<ExplorerIcon size={48} />}
              message="Select a file from the tree to view its contents"
            />
          )}
          {selectedPath && (
            <CodeViewer
              filePath={selectedPath}
              findings={findings || undefined}
              highlights={codeHighlights}
              highlightLine={highlightLine}
              flowLines={flowLineSet.size > 0 ? flowLineSet : undefined}
              language={language}
            />
          )}
        </div>
      </div>

      {/* Right panel */}
      <div className="explorer-right">
        {!selectedPath && (
          <div className="explorer-right-section">
            <div className="explorer-hint">Select a file to view analysis details</div>
          </div>
        )}

        {selectedPath && (
          <>
            {/* File summary */}
            <div className="explorer-right-section">
              <h3>File Summary</h3>
              <div className="explorer-file-meta">
                {language && <span className="badge">{language}</span>}
                <span className="meta-text">
                  {findings ? findings.length : 0} finding{findings?.length !== 1 ? 's' : ''}
                </span>
              </div>
              {findings && findings.length > 0 && (
                <div className="explorer-sev-breakdown">
                  {Object.entries(sevBreakdown)
                    .sort(([a], [b]) => sevOrder(a) - sevOrder(b))
                    .map(([sev, count]) => (
                      <span
                        key={sev}
                        className={`badge badge-sev badge-sev-${sev.toLowerCase()}`}
                      >
                        {sev}: {count}
                      </span>
                    ))}
                </div>
              )}
            </div>

            {/* Symbols */}
            <div className="explorer-right-section">
              <h3>Symbols</h3>
              {symbols && symbols.length === 0 && (
                <div className="explorer-hint">No symbols found</div>
              )}
              {symbols &&
                symbols.map((sym, i) => (
                  <div key={`${sym.name}-${i}`} className="explorer-symbol-item compact">
                    <span className={`symbol-kind symbol-kind-${sym.kind}`}>
                      {sym.kind === 'function' ? 'ƒ' : 'm'}
                    </span>
                    <span className="symbol-name">{sym.name}</span>
                  </div>
                ))}
            </div>

            {/* Findings */}
            <div className="explorer-right-section">
              <h3>Findings</h3>
              {findings && findings.length === 0 && (
                <div className="explorer-hint">No findings in this file</div>
              )}
              <div className="explorer-findings-list">
                {findings &&
                  findings.map((f) => (
                    <div
                      key={`${f.line}-${f.rule_id}`}
                      className={`explorer-finding-item${selectedFindingIndex === f.index ? ' active' : ''}`}
                      onClick={() => handleSelectFinding(f.index, f.line)}
                    >
                      <span className={`finding-sev-dot sev-${f.severity.toLowerCase()}`} />
                      <span className="finding-line">L{f.line}</span>
                      <span className="finding-rule">{f.rule_id}</span>
                      {f.message && (
                        <span className="finding-msg" title={f.message}>
                          {f.message}
                        </span>
                      )}
                    </div>
                  ))}
              </div>
            </div>

            {/* Taint Flow (shown when a taint finding is selected) */}
            {hasFlow && (
              <div className="explorer-right-section">
                <h3>Taint Flow</h3>
                <ExplorerFlowTimeline
                  steps={flowSteps}
                  onStepClick={(line) => setHighlightLine(line)}
                />
              </div>
            )}

            {/* State Evidence (shown when a state finding is selected) */}
            {hasStateEvidence && fullFinding && (
              <ExplorerStateDetail finding={fullFinding} />
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ── Flow Timeline (compact version for explorer) ────────────────────────────

function ExplorerFlowTimeline({
  steps,
  onStepClick,
}: {
  steps: FlowStep[];
  onStepClick: (line: number) => void;
}) {
  return (
    <div className="flow-timeline explorer-flow">
      {steps.map((s, i) => {
        const color = FLOW_KIND_COLORS[s.kind] || 'var(--text-secondary)';
        const label = FLOW_KIND_LABELS[s.kind] || s.kind;
        const isLast = i === steps.length - 1;

        return (
          <div
            key={i}
            className={`flow-step${s.is_cross_file ? ' flow-step-cross-file' : ''}`}
            onClick={() => s.line && onStepClick(s.line)}
          >
            <div className="flow-step-connector">
              <div className="flow-step-dot" style={{ background: color }} />
              {!isLast && <div className="flow-step-line" />}
            </div>
            <div className="flow-step-card">
              <div className="flow-step-header">
                <span className="flow-step-badge" style={{ color }}>
                  {label}
                </span>
                {s.variable && (
                  <span className="flow-step-var">{s.variable}</span>
                )}
                {s.callee && (
                  <span className="flow-step-callee">{s.callee}</span>
                )}
              </div>
              <div className="flow-step-loc">
                L{s.line}:{s.col}
                {s.function ? ` in ${s.function}` : ''}
              </div>
              {s.snippet && <div className="flow-step-snippet">{s.snippet}</div>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── State Evidence (compact version for explorer) ────────────────────────────

const STATE_REMEDIATION_HINTS: Record<string, string> = {
  'state-use-after-close':
    'Ensure the resource is not accessed after calling close/free.',
  'state-double-close':
    'Remove the duplicate close call, or guard with a null/closed check.',
  'state-resource-leak':
    'Add a close/free call before the function exits, or use defer/with/try-with-resources/RAII.',
  'state-resource-leak-possible':
    'Ensure the resource is closed on all code paths, including error/early-return paths.',
  'state-unauthed-access':
    'Add an authentication check before this operation, or move it behind auth middleware.',
};

function ExplorerStateDetail({ finding }: { finding: FindingView }) {
  const st = finding.evidence?.state;
  if (!st) return null;

  const isAuth = st.machine === 'auth';
  const machineLabel = isAuth ? 'Authentication State' : 'Resource Lifecycle';
  const hint = STATE_REMEDIATION_HINTS[finding.rule_id];
  const acquireLocation =
    (finding.rule_id.includes('leak') && finding.evidence?.sink)
      ? `L${finding.evidence.sink.line}:${finding.evidence.sink.col}`
      : null;

  return (
    <div className="explorer-right-section">
      <h3>State Analysis</h3>
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
          <div className="state-acquire-location">Acquired at: {acquireLocation}</div>
        )}
      </div>
      {hint && (
        <div className="state-remediation">
          <div className="state-remediation-label">Remediation</div>
          {hint}
        </div>
      )}
    </div>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function findEntry(
  rootEntries: TreeEntry[] | undefined,
  loadedChildren: Map<string, TreeEntry[]>,
  path: string | null,
): TreeEntry | undefined {
  if (!path) return undefined;

  if (rootEntries) {
    const found = rootEntries.find((e) => e.path === path);
    if (found) return found;
  }

  for (const children of loadedChildren.values()) {
    const found = children.find((e) => e.path === path);
    if (found) return found;
  }

  return undefined;
}

function buildHotspotList(
  rootEntries: TreeEntry[] | undefined,
  loadedChildren: Map<string, TreeEntry[]>,
): TreeEntry[] {
  const files: TreeEntry[] = [];

  function collect(entries: TreeEntry[]) {
    for (const e of entries) {
      if (e.entry_type === 'file' && e.finding_count > 0) {
        files.push(e);
      }
      if (e.entry_type === 'dir') {
        const children = loadedChildren.get(e.path);
        if (children) collect(children);
      }
    }
  }

  if (rootEntries) collect(rootEntries);
  files.sort((a, b) => b.finding_count - a.finding_count);
  return files;
}

function sevOrder(sev: string): number {
  switch (sev) {
    case 'HIGH':
      return 0;
    case 'MEDIUM':
      return 1;
    case 'LOW':
      return 2;
    default:
      return 3;
  }
}
