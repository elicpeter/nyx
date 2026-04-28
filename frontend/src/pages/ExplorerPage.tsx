import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  useExplorerSymbols,
  useExplorerFindings,
} from '../api/queries/explorer';
import { useFinding } from '../api/queries/findings';
import { useDebugFunctions } from '../api/queries/debug';
import { ApiError } from '../api/client';
import { FileTree } from '../components/data-display/FileTree';
import { CodeViewer } from '../components/data-display/CodeViewer';
import { LoadingState } from '../components/ui/LoadingState';
import { usePageTitle } from '../hooks/usePageTitle';
import { EmptyState } from '../components/ui/EmptyState';
import { ExplorerIcon } from '../components/icons/Icons';
import { useFileTree } from '../hooks/useFileTree';
import { FunctionSelector } from './debug/FunctionSelector';
import { CfgAnalysisPanel } from './debug/CfgViewerPage';
import { SsaAnalysisPanel } from './debug/SsaViewerPage';
import { TaintAnalysisPanel } from './debug/TaintViewerPage';
import { SummaryAnalysisPanel } from './debug/SummaryExplorerPage';
import { AbstractInterpAnalysisPanel } from './debug/AbstractInterpPage';
import { SymexAnalysisPanel } from './debug/SymexPage';
import { PointerAnalysisPanel } from './debug/PointerViewerPage';
import { TypeFactsAnalysisPanel } from './debug/TypeFactsPage';
import type { TreeEntry, FlowStep, FindingView } from '../api/types';

type ExplorerMode = 'tree' | 'symbols' | 'hotspots';
type ExplorerView =
  | 'code'
  | 'cfg'
  | 'ssa'
  | 'taint'
  | 'summaries'
  | 'abstract-interp'
  | 'symex'
  | 'pointer'
  | 'type-facts';

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

const VIEW_CONFIG: Array<{
  id: ExplorerView;
  label: string;
  requiresFunction?: boolean;
  supportsFunction?: boolean;
}> = [
  { id: 'code', label: 'Code' },
  { id: 'cfg', label: 'CFG', requiresFunction: true, supportsFunction: true },
  { id: 'ssa', label: 'SSA', requiresFunction: true, supportsFunction: true },
  {
    id: 'taint',
    label: 'Taint',
    requiresFunction: true,
    supportsFunction: true,
  },
  { id: 'summaries', label: 'Summaries', supportsFunction: true },
  {
    id: 'abstract-interp',
    label: 'Abstract Interp',
    requiresFunction: true,
    supportsFunction: true,
  },
  {
    id: 'symex',
    label: 'Symex',
    requiresFunction: true,
    supportsFunction: true,
  },
  {
    id: 'pointer',
    label: 'Pointer',
    requiresFunction: true,
    supportsFunction: true,
  },
  {
    id: 'type-facts',
    label: 'Type Facts',
    requiresFunction: true,
    supportsFunction: true,
  },
];

const VIEW_CONFIG_BY_ID = new Map(VIEW_CONFIG.map((view) => [view.id, view]));

export function ExplorerPage() {
  usePageTitle('Explorer');
  const [params, setParams] = useSearchParams();
  const [explorerMode, setExplorerMode] = useState<ExplorerMode>('tree');
  const [showClosures, setShowClosures] = useState(false);
  const [highlightLine, setHighlightLine] = useState<number | undefined>();
  const [selectedFindingIndex, setSelectedFindingIndex] = useState<
    number | null
  >(null);
  const [invalidFunctionNotice, setInvalidFunctionNotice] = useState<
    string | null
  >(null);
  const codeScrollPositionsRef = useRef<Record<string, number>>({});

  const rawView = params.get('view');
  const rawFile = params.get('file') || null;
  const rawFunction = params.get('function') || null;
  const currentView: ExplorerView = isExplorerView(rawView) ? rawView : 'code';
  const currentViewConfig = VIEW_CONFIG_BY_ID.get(currentView)!;
  const isCodeView = currentView === 'code';

  const updateExplorerParams = useCallback(
    (
      updates: Partial<Record<'file' | 'view' | 'function', string | null>>,
      replace = false,
    ) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [key, value] of Object.entries(updates)) {
            if (value) {
              next.set(key, value);
            } else {
              next.delete(key);
            }
          }
          return next;
        },
        { replace },
      );
    },
    [setParams],
  );

  useEffect(() => {
    if (rawView !== currentView) {
      updateExplorerParams({ view: currentView }, true);
    }
  }, [currentView, rawView, updateExplorerParams]);

  const { data: symbolEntries, error: symbolsError } =
    useExplorerSymbols(rawFile);

  const closureSymbolCount = useMemo(
    () =>
      symbolEntries?.filter((s) => s.func_kind === 'closure').length ?? 0,
    [symbolEntries],
  );

  const visibleSymbolEntries = useMemo(() => {
    if (!symbolEntries) return symbolEntries;
    return showClosures
      ? symbolEntries
      : symbolEntries.filter((s) => s.func_kind !== 'closure');
  }, [symbolEntries, showClosures]);
  const hasInvalidFile = Boolean(
    rawFile && isPathResolutionError(symbolsError),
  );
  const hasFileLookupError = Boolean(
    rawFile && symbolsError && !hasInvalidFile,
  );
  const selectedFile = rawFile && !hasInvalidFile ? rawFile : null;

  const handleFileSelect = useCallback(
    (path: string) => {
      setHighlightLine(undefined);
      setSelectedFindingIndex(null);
      setInvalidFunctionNotice(null);
      updateExplorerParams({ file: path, function: null });
    },
    [updateExplorerParams],
  );

  const {
    rootEntries,
    isLoading: treeLoading,
    expandedPaths,
    loadedChildren,
    selectedPath,
    handleToggleExpand,
    handleSelectFile,
  } = useFileTree(selectedFile, handleFileSelect);

  const { data: functions, isLoading: functionsLoading } =
    useDebugFunctions(selectedFile);
  const selectedFunction =
    rawFunction && functions?.some((fn) => fn.name === rawFunction)
      ? rawFunction
      : null;
  const hasFunctionOptions = (functions?.length ?? 0) > 0;

  useEffect(() => {
    if (!rawFunction) {
      return;
    }

    if (!selectedFile) {
      setInvalidFunctionNotice(
        `Function "${rawFunction}" was cleared because no valid file is selected.`,
      );
      updateExplorerParams({ function: null }, true);
      return;
    }

    if (!functions) {
      return;
    }

    if (!functions.some((fn) => fn.name === rawFunction)) {
      setInvalidFunctionNotice(
        `Function "${rawFunction}" was not found in ${selectedFile}.`,
      );
      updateExplorerParams({ function: null }, true);
    }
  }, [functions, rawFunction, selectedFile, updateExplorerParams]);

  const { data: findings } = useExplorerFindings(selectedFile);
  const { data: fullFinding } = useFinding(selectedFindingIndex ?? '');

  const handleSelectFinding = useCallback((index: number, line: number) => {
    setSelectedFindingIndex(index);
    setHighlightLine(line);
  }, []);

  const handleViewSelect = useCallback(
    (view: ExplorerView) => {
      updateExplorerParams({ view });
    },
    [updateExplorerParams],
  );

  const handleFunctionChange = useCallback(
    (fnName: string | null) => {
      setInvalidFunctionNotice(null);
      updateExplorerParams({ function: fnName });
    },
    [updateExplorerParams],
  );

  const selectedEntry = findEntry(rootEntries, loadedChildren, selectedFile);
  const language = selectedEntry?.language || '';
  const hotspotFiles = useMemo(
    () => buildHotspotList(rootEntries, loadedChildren),
    [loadedChildren, rootEntries],
  );

  const sevBreakdown = findings
    ? findings.reduce(
        (acc, finding) => {
          const key = finding.severity.toUpperCase();
          acc[key] = (acc[key] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      )
    : {};

  const evidence = fullFinding?.evidence;
  const flowSteps = evidence?.flow_steps;
  const hasFlow = flowSteps && flowSteps.length > 0;
  const hasStateEvidence =
    fullFinding?.rule_id.startsWith('state-') && evidence?.state;

  const codeHighlights =
    selectedFindingIndex != null && evidence
      ? {
          sourceLine: evidence.source?.line,
          sinkLine: evidence.sink?.line,
          findingLine: fullFinding?.line,
        }
      : undefined;

  const flowLineSet = new Set<number>();
  if (hasFlow) {
    for (const step of flowSteps) {
      if (step.line) {
        flowLineSet.add(step.line);
      }
    }
  }

  const analysisContent = renderAnalysisContent({
    currentView,
    currentViewLabel: currentViewConfig.label,
    selectedFile,
    selectedFunction,
    functions,
    functionsLoading,
    onBrowseFiles: () => handleViewSelect('code'),
  });

  return (
    <div
      className={`explorer-page ${isCodeView ? 'explorer-page-code' : 'explorer-page-analysis'}`}
    >
      <div className="explorer-left">
        <div className="explorer-left-header">
          <div className="explorer-mode-toggle">
            {(['tree', 'symbols', 'hotspots'] as ExplorerMode[]).map((mode) => (
              <button
                key={mode}
                className={`mode-btn${explorerMode === mode ? ' active' : ''}`}
                onClick={() => setExplorerMode(mode)}
              >
                {mode === 'tree'
                  ? 'Files'
                  : mode === 'symbols'
                    ? 'Symbols'
                    : 'Hotspots'}
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
              {!selectedFile && (
                <div className="explorer-hint">
                  Select a file to view symbols
                </div>
              )}
              {selectedFile && symbolEntries && symbolEntries.length === 0 && (
                <div className="explorer-hint">No symbols found</div>
              )}
              {selectedFile && closureSymbolCount > 0 && (
                <label className="explorer-symbol-toggle">
                  <input
                    type="checkbox"
                    checked={showClosures}
                    onChange={(e) => setShowClosures(e.target.checked)}
                  />
                  <span>
                    Show {closureSymbolCount} anonymous closure
                    {closureSymbolCount === 1 ? '' : 's'}
                  </span>
                </label>
              )}
              {selectedFile &&
                visibleSymbolEntries?.map((sym, index) => (
                  <div
                    key={`${sym.name}-${index}`}
                    className="explorer-symbol-item"
                  >
                    <span className={`symbol-kind symbol-kind-${sym.kind}`}>
                      {sym.kind === 'function' ? 'ƒ' : 'm'}
                    </span>
                    <span className="symbol-name">{sym.name}</span>
                    {sym.arity !== undefined && sym.arity !== null && (
                      <span className="symbol-arity">({sym.arity})</span>
                    )}
                    {sym.func_kind === 'closure' && (
                      <span
                        className="text-secondary"
                        style={{ marginLeft: 6, fontSize: '0.85em' }}
                      >
                        {sym.container
                          ? `[closure in ${sym.container}]`
                          : '[closure]'}
                      </span>
                    )}
                    {sym.finding_count > 0 && (
                      <span className="tree-node-badge">
                        {sym.finding_count}
                      </span>
                    )}
                  </div>
                ))}
            </div>
          )}

          {explorerMode === 'hotspots' && (
            <div className="explorer-hotspot-list">
              {hotspotFiles.length === 0 && (
                <div className="explorer-hint">
                  No findings in scanned files
                </div>
              )}
              {hotspotFiles.map((entry) => (
                <div
                  key={entry.path}
                  className={`hotspot-item${selectedFile === entry.path ? ' selected' : ''}`}
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

      <div className="explorer-main-shell">
        <div className="explorer-file-header">
          <div className="explorer-file-header-top">
            <div className="explorer-file-header-copy">
              <span className="explorer-file-label">File</span>
              <span className="explorer-file-path">
                {selectedFile || 'Select a file in Explorer'}
              </span>
            </div>
            {selectedFile && currentViewConfig.supportsFunction && (
              <div className="explorer-function-picker">
                <FunctionSelector
                  file={selectedFile}
                  selectedFunction={selectedFunction}
                  onFunctionChange={handleFunctionChange}
                  showFilePath={false}
                />
              </div>
            )}
          </div>
          <div
            className="explorer-view-tabs"
            role="tablist"
            aria-label="File views"
          >
            {VIEW_CONFIG.map((view) => (
              <button
                key={view.id}
                className={`explorer-view-tab${currentView === view.id ? ' active' : ''}`}
                onClick={() => handleViewSelect(view.id)}
                type="button"
              >
                {view.label}
              </button>
            ))}
          </div>
          {hasInvalidFile && rawFile && (
            <div className="explorer-inline-notice">
              The requested file <code>{rawFile}</code> could not be found.
              Choose another file in Explorer.
            </div>
          )}
          {hasFileLookupError && (
            <div className="explorer-inline-notice explorer-inline-notice-warning">
              Explorer could not validate the selected file right now.
            </div>
          )}
          {invalidFunctionNotice && (
            <div className="explorer-inline-notice">
              {invalidFunctionNotice}
            </div>
          )}
        </div>

        <div className="explorer-main-body">
          {isCodeView ? (
            <>
              {!selectedFile && (
                <EmptyState
                  icon={<ExplorerIcon size={48} />}
                  message={
                    hasInvalidFile
                      ? 'Choose a file from the Explorer to continue.'
                      : 'Select a file from the tree to view its contents.'
                  }
                />
              )}
              {selectedFile && (
                <CodeViewer
                  filePath={selectedFile}
                  findings={findings || undefined}
                  highlights={codeHighlights}
                  highlightLine={highlightLine}
                  flowLines={flowLineSet.size > 0 ? flowLineSet : undefined}
                  language={language}
                  initialScrollTop={
                    codeScrollPositionsRef.current[selectedFile]
                  }
                  onScrollPositionChange={(scrollTop) => {
                    codeScrollPositionsRef.current[selectedFile] = scrollTop;
                  }}
                />
              )}
            </>
          ) : (
            analysisContent
          )}
        </div>
      </div>

      {isCodeView && (
        <div className="explorer-right">
          {!selectedFile && (
            <div className="explorer-right-section">
              <div className="explorer-hint">
                Select a file to view analysis details
              </div>
            </div>
          )}

          {selectedFile && (
            <>
              <div className="explorer-right-section">
                <h3>File Summary</h3>
                <div className="explorer-file-meta">
                  {language && <span className="badge">{language}</span>}
                  <span className="meta-text">
                    {findings ? findings.length : 0} finding
                    {findings?.length !== 1 ? 's' : ''}
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

              <div className="explorer-right-section">
                <h3>Symbols</h3>
                {symbolEntries && symbolEntries.length === 0 && (
                  <div className="explorer-hint">No symbols found</div>
                )}
                {visibleSymbolEntries?.map((sym, index) => (
                  <div
                    key={`${sym.name}-${index}`}
                    className="explorer-symbol-item compact"
                  >
                    <span className={`symbol-kind symbol-kind-${sym.kind}`}>
                      {sym.kind === 'function' ? 'ƒ' : 'm'}
                    </span>
                    <span className="symbol-name">{sym.name}</span>
                    {sym.func_kind === 'closure' && (
                      <span
                        className="text-secondary"
                        style={{ marginLeft: 6, fontSize: '0.85em' }}
                      >
                        [closure]
                      </span>
                    )}
                  </div>
                ))}
                {!showClosures && closureSymbolCount > 0 && (
                  <button
                    className="explorer-symbol-toggle-link"
                    type="button"
                    onClick={() => setShowClosures(true)}
                  >
                    Show {closureSymbolCount} closure
                    {closureSymbolCount === 1 ? '' : 's'}
                  </button>
                )}
              </div>

              <div className="explorer-right-section">
                <h3>Findings</h3>
                {findings && findings.length === 0 && (
                  <div className="explorer-hint">No findings in this file</div>
                )}
                <div className="explorer-findings-list">
                  {findings?.map((finding) => (
                    <div
                      key={`${finding.line}-${finding.rule_id}`}
                      className={`explorer-finding-item${selectedFindingIndex === finding.index ? ' active' : ''}`}
                      onClick={() =>
                        handleSelectFinding(finding.index, finding.line)
                      }
                    >
                      <span
                        className={`finding-sev-dot sev-${finding.severity.toLowerCase()}`}
                      />
                      <span className="finding-line">L{finding.line}</span>
                      <span className="finding-rule">{finding.rule_id}</span>
                      {finding.message && (
                        <span className="finding-msg" title={finding.message}>
                          {finding.message}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {hasFlow && (
                <div className="explorer-right-section">
                  <h3>Taint Flow</h3>
                  <ExplorerFlowTimeline
                    steps={flowSteps}
                    onStepClick={(line) => setHighlightLine(line)}
                  />
                </div>
              )}

              {hasStateEvidence && fullFinding && (
                <ExplorerStateDetail finding={fullFinding} />
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function renderAnalysisContent({
  currentView,
  currentViewLabel,
  selectedFile,
  selectedFunction,
  functions,
  functionsLoading,
  onBrowseFiles,
}: {
  currentView: ExplorerView;
  currentViewLabel: string;
  selectedFile: string | null;
  selectedFunction: string | null;
  functions: Array<{ name: string }> | undefined;
  functionsLoading: boolean;
  onBrowseFiles: () => void;
}) {
  if (!selectedFile) {
    return (
      <EmptyState
        icon={<ExplorerIcon size={48} />}
        message="Select a file from the tree to view its contents."
      />
    );
  }

  if (currentView === 'summaries') {
    return (
      <div className="explorer-analysis-content">
        <SummaryAnalysisPanel
          file={selectedFile}
          functionName={selectedFunction}
          scope="file"
        />
      </div>
    );
  }

  if (functionsLoading) {
    return <LoadingState message="Loading functions..." />;
  }

  if ((functions?.length ?? 0) === 0) {
    return (
      <AnalysisEmptyState
        title="No functions found"
        message="This file does not expose any functions for function-scoped analysis."
      />
    );
  }

  if (!selectedFunction) {
    return (
      <AnalysisEmptyState
        title={`Select a function to inspect ${currentViewLabel}`}
        message={`Choose a function in the header to view ${currentViewLabel.toLowerCase()} for this file.`}
      />
    );
  }

  switch (currentView) {
    case 'cfg':
      return (
        <CfgAnalysisPanel file={selectedFile} functionName={selectedFunction} />
      );
    case 'ssa':
      return (
        <div className="explorer-analysis-content">
          <SsaAnalysisPanel
            file={selectedFile}
            functionName={selectedFunction}
          />
        </div>
      );
    case 'taint':
      return (
        <div className="explorer-analysis-content">
          <TaintAnalysisPanel
            file={selectedFile}
            functionName={selectedFunction}
          />
        </div>
      );
    case 'abstract-interp':
      return (
        <div className="explorer-analysis-content">
          <AbstractInterpAnalysisPanel
            file={selectedFile}
            functionName={selectedFunction}
          />
        </div>
      );
    case 'symex':
      return (
        <div className="explorer-analysis-content">
          <SymexAnalysisPanel
            file={selectedFile}
            functionName={selectedFunction}
          />
        </div>
      );
    case 'pointer':
      return (
        <div className="explorer-analysis-content">
          <PointerAnalysisPanel
            file={selectedFile}
            functionName={selectedFunction}
          />
        </div>
      );
    case 'type-facts':
      return (
        <div className="explorer-analysis-content">
          <TypeFactsAnalysisPanel
            file={selectedFile}
            functionName={selectedFunction}
          />
        </div>
      );
    case 'code':
      return null;
  }
}

function AnalysisEmptyState({
  title,
  message,
  onBrowseFiles,
}: {
  title: string;
  message: string;
  onBrowseFiles?: () => void;
}) {
  return (
    <EmptyState>
      <h3>{title}</h3>
      <p>{message}</p>
      {onBrowseFiles && (
        <button className="btn btn-primary btn-sm" onClick={onBrowseFiles}>
          Browse Files
        </button>
      )}
    </EmptyState>
  );
}

function ExplorerFlowTimeline({
  steps,
  onStepClick,
}: {
  steps: FlowStep[];
  onStepClick: (line: number) => void;
}) {
  return (
    <div className="flow-timeline explorer-flow">
      {steps.map((step, index) => {
        const color = FLOW_KIND_COLORS[step.kind] || 'var(--text-secondary)';
        const label = FLOW_KIND_LABELS[step.kind] || step.kind;
        const isLast = index === steps.length - 1;

        return (
          <div
            key={index}
            className={`flow-step${step.is_cross_file ? ' flow-step-cross-file' : ''}`}
            onClick={() => step.line && onStepClick(step.line)}
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
                {step.variable && (
                  <span className="flow-step-var">{step.variable}</span>
                )}
                {step.callee && (
                  <span className="flow-step-callee">{step.callee}</span>
                )}
              </div>
              <div className="flow-step-loc">
                L{step.line}:{step.col}
                {step.function ? ` in ${step.function}` : ''}
              </div>
              {step.snippet && (
                <div className="flow-step-snippet">{step.snippet}</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

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
  const state = finding.evidence?.state;
  if (!state) {
    return null;
  }

  const isAuth = state.machine === 'auth';
  const machineLabel = isAuth ? 'Authentication State' : 'Resource Lifecycle';
  const hint = STATE_REMEDIATION_HINTS[finding.rule_id];
  const acquireLocation =
    finding.rule_id.includes('leak') && finding.evidence?.sink
      ? `L${finding.evidence.sink.line}:${finding.evidence.sink.col}`
      : null;

  return (
    <div className="explorer-right-section">
      <h3>State Analysis</h3>
      <div className="state-transition-card">
        <div className="state-machine-label">{machineLabel}</div>
        {state.subject && (
          <div className="state-subject">
            <span className="state-subject-label">Variable:</span>
            <code className="state-subject-name">{state.subject}</code>
          </div>
        )}
        <div className="state-transition-visual">
          <span className="state-from">{state.from_state}</span>
          <span className="state-arrow">&rarr;</span>
          <span className="state-to">{state.to_state}</span>
        </div>
        {acquireLocation && (
          <div className="state-acquire-location">
            Acquired at: {acquireLocation}
          </div>
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

function findEntry(
  rootEntries: TreeEntry[] | undefined,
  loadedChildren: Map<string, TreeEntry[]>,
  path: string | null,
): TreeEntry | undefined {
  if (!path) {
    return undefined;
  }

  if (rootEntries) {
    const found = rootEntries.find((entry) => entry.path === path);
    if (found) {
      return found;
    }
  }

  for (const children of loadedChildren.values()) {
    const found = children.find((entry) => entry.path === path);
    if (found) {
      return found;
    }
  }

  return undefined;
}

function buildHotspotList(
  rootEntries: TreeEntry[] | undefined,
  loadedChildren: Map<string, TreeEntry[]>,
): TreeEntry[] {
  const files: TreeEntry[] = [];

  function collect(entries: TreeEntry[]) {
    for (const entry of entries) {
      if (entry.entry_type === 'file' && entry.finding_count > 0) {
        files.push(entry);
      }
      if (entry.entry_type === 'dir') {
        const children = loadedChildren.get(entry.path);
        if (children) {
          collect(children);
        }
      }
    }
  }

  if (rootEntries) {
    collect(rootEntries);
  }
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

function isExplorerView(value: string | null): value is ExplorerView {
  return VIEW_CONFIG_BY_ID.has(value as ExplorerView);
}

function isPathResolutionError(error: unknown): boolean {
  return (
    error instanceof ApiError && (error.status === 403 || error.status === 404)
  );
}
