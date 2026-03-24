// Evidence types (from src/evidence.rs)
export type Confidence = 'Low' | 'Medium' | 'High';
export type FlowStepKind = 'source' | 'assignment' | 'call' | 'phi' | 'sink';

export interface FlowStep {
  step: number;
  kind: FlowStepKind;
  file: string;
  line: number;
  col: number;
  snippet?: string;
  variable?: string;
  callee?: string;
  function?: string;
  is_cross_file?: boolean;
}

export interface SpanEvidence {
  path: string;
  line: number;
  col: number;
  kind: string;
  snippet?: string;
}

export interface StateEvidence {
  machine: string;
  subject?: string;
  from_state: string;
  to_state: string;
}

export interface Evidence {
  source?: SpanEvidence;
  sink?: SpanEvidence;
  guards: SpanEvidence[];
  sanitizers: SpanEvidence[];
  state?: StateEvidence;
  notes: string[];
  flow_steps: FlowStep[];
  explanation?: string;
  confidence_limiters: string[];
}

// Finding types
export interface CodeContextView {
  start_line: number;
  lines: string[];
  highlight_line: number;
}

export interface RelatedFindingView {
  index: number;
  rule_id: string;
  path: string;
  line: number;
  severity: string;
}

export interface FindingView {
  index: number;
  fingerprint: string;
  portable_fingerprint?: string;
  path: string;
  line: number;
  col: number;
  severity: string;
  rule_id: string;
  category: string;
  confidence?: Confidence;
  rank_score?: number;
  message?: string;
  labels: [string, string][];
  path_validated: boolean;
  suppressed: boolean;
  language?: string;
  status: string;
  triage_state: string;
  triage_note?: string;
  code_context?: CodeContextView;
  evidence?: Evidence;
  guard_kind?: string;
  rank_reason?: [string, string][];
  sanitizer_status?: string;
  related_findings: RelatedFindingView[];
}

export interface FindingSummary {
  total: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_rule: Record<string, number>;
  by_file: Record<string, number>;
}

export interface FilterValues {
  severities: string[];
  categories: string[];
  confidences: string[];
  languages: string[];
  rules: string[];
  statuses: string[];
}

// Scan types
export interface TimingBreakdown {
  walk_ms: number;
  pass1_ms: number;
  call_graph_ms: number;
  pass2_ms: number;
  post_process_ms: number;
}

export interface ScanMetricsSnapshot {
  cfg_nodes: number;
  call_edges: number;
  functions_analyzed: number;
  summaries_reused: number;
  unresolved_calls: number;
}

export interface ScanView {
  id: string;
  status: string;
  scan_root: string;
  started_at?: string;
  finished_at?: string;
  duration_secs?: number;
  finding_count?: number;
  error?: string;
  engine_version?: string;
  languages?: string[];
  files_scanned?: number;
  timing?: TimingBreakdown;
  metrics?: ScanMetricsSnapshot;
}

// Scan Comparison types
export interface CompareScanInfo {
  id: string;
  started_at?: string;
  finding_count: number;
}

export interface CompareSummary {
  new_count: number;
  fixed_count: number;
  changed_count: number;
  unchanged_count: number;
  severity_delta: Record<string, number>;
}

export interface ComparedFinding extends FindingView {
  fingerprint: string;
}

export interface FieldChange {
  field: string;
  old_value: string;
  new_value: string;
}

export interface ChangedFinding extends FindingView {
  fingerprint: string;
  changes: FieldChange[];
}

export interface CompareResponse {
  left_scan: CompareScanInfo;
  right_scan: CompareScanInfo;
  summary: CompareSummary;
  new_findings: ComparedFinding[];
  fixed_findings: ComparedFinding[];
  changed_findings: ChangedFinding[];
  unchanged_findings: ComparedFinding[];
}

// Overview types
export interface OverviewCount {
  name: string;
  count: number;
}

export interface NoisyRule {
  rule_id: string;
  finding_count: number;
  suppression_rate: number;
}

export interface ScanSummary {
  id: string;
  status: string;
  started_at?: string;
  duration_secs?: number;
  finding_count?: number;
}

export interface Insight {
  kind: string;
  message: string;
  severity: string;
  action_url?: string;
}

export interface TrendPoint {
  scan_id: string;
  timestamp: string;
  total: number;
  by_severity: Record<string, number>;
}

export interface OverviewResponse {
  state: string;
  total_findings: number;
  new_since_last: number;
  fixed_since_last: number;
  high_confidence_rate: number;
  triage_coverage: number;
  latest_scan_duration_secs?: number;
  latest_scan_id?: string;
  latest_scan_at?: string;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_language: Record<string, number>;
  top_files: OverviewCount[];
  top_directories: OverviewCount[];
  top_rules: OverviewCount[];
  noisy_rules: NoisyRule[];
  recent_scans: ScanSummary[];
  insights: Insight[];
}

// Rules types
export interface RuleListItem {
  id: string;
  title: string;
  language: string;
  kind: string;
  cap: string;
  matchers: string[];
  enabled: boolean;
  is_custom: boolean;
  is_gated: boolean;
  case_sensitive: boolean;
  finding_count: number;
  suppression_rate: number;
}

export interface RuleDetailView extends RuleListItem {
  example_findings: RelatedFindingView[];
}

// Config types
export interface RuleView {
  lang: string;
  matchers: string[];
  kind: string;
  cap: string;
}

export interface TerminatorView {
  lang: string;
  name: string;
}

export interface LabelEntryView {
  lang: string;
  matchers: string[];
  cap: string;
  case_sensitive: boolean;
  is_builtin: boolean;
}

export interface ProfileView {
  name: string;
  is_builtin: boolean;
  settings: Record<string, unknown>;
}

// Health
export interface HealthResponse {
  status: string;
  version: string;
  scan_root: string;
}

// Paginated response wrappers
export interface PaginatedFindings {
  findings: FindingView[];
  total: number;
  page: number;
  per_page: number;
}

// Triage types
export interface TriageEntry {
  fingerprint: string;
  state: string;
  note: string;
  updated_at: string;
  finding?: FindingView;
}

export interface PaginatedTriage {
  entries: TriageEntry[];
  total: number;
  page: number;
  per_page: number;
}

export interface AuditEntry {
  id: number;
  fingerprint: string;
  action: string;
  previous_state: string;
  new_state: string;
  note: string;
  timestamp: string;
}

export interface PaginatedAudit {
  entries: AuditEntry[];
  total: number;
  page: number;
  per_page: number;
}

export interface SuppressionRule {
  id: number;
  suppress_by: string;
  match_value: string;
  state: string;
  note: string;
  created_at: string;
}

export interface SyncStatus {
  file_path: string;
  file_exists: boolean;
  sync_enabled: boolean;
  decisions: number;
  suppression_rules: number;
}

// File viewer
export interface FileResponse {
  path: string;
  lines: { number: number; content: string }[];
  total_lines: number;
}

// Explorer types
export interface TreeEntry {
  name: string;
  entry_type: 'file' | 'dir';
  path: string;
  language?: string;
  finding_count: number;
  severity_max?: string;
}

export interface SymbolEntry {
  name: string;
  kind: string;
  line?: number;
  finding_count: number;
  namespace?: string;
  arity?: number;
}

export interface ExplorerFinding {
  index: number;
  line: number;
  col: number;
  severity: string;
  rule_id: string;
  category: string;
  message?: string;
  confidence?: string;
}

// Scan log entry
export interface ScanLogEntry {
  timestamp: string;
  level: string;
  message: string;
  file_path?: string;
  detail?: string;
}

// ── Debug view types ─────────────────────────────────────────────────────────

export interface FunctionInfo {
  name: string;
  namespace: string;
  param_count: number;
  line: number;
  source_caps: string[];
  sanitizer_caps: string[];
  sink_caps: string[];
}

// CFG
export interface CfgNodeView {
  id: number;
  kind: string;
  span: [number, number];
  line: number;
  defines?: string;
  uses: string[];
  callee?: string;
  labels: string[];
  condition_text?: string;
  enclosing_func?: string;
}

export interface CfgEdgeView {
  source: number;
  target: number;
  kind: string;
}

export interface CfgGraphView {
  nodes: CfgNodeView[];
  edges: CfgEdgeView[];
  entry: number;
}

// SSA
export interface SsaInstView {
  value: number;
  op: string;
  operands: string[];
  var_name?: string;
  span: [number, number];
  line: number;
}

export interface SsaBlockView {
  id: number;
  phis: SsaInstView[];
  body: SsaInstView[];
  terminator: string;
  preds: number[];
  succs: number[];
}

export interface SsaBodyView {
  blocks: SsaBlockView[];
  entry: number;
  num_values: number;
}

// Taint
export interface TaintValueView {
  ssa_value: number;
  var_name?: string;
  caps: string[];
  uses_summary: boolean;
}

export interface TaintBlockStateView {
  block_id: number;
  values: TaintValueView[];
  validated_must: number;
  validated_may: number;
}

export interface TaintEventView {
  sink_node: number;
  sink_caps: string[];
  tainted_values: TaintValueView[];
  all_validated: boolean;
  uses_summary: boolean;
}

export interface TaintAnalysisView {
  block_states: TaintBlockStateView[];
  events: TaintEventView[];
}

// Abstract Interpretation
export interface AbstractValueView {
  ssa_value: number;
  var_name?: string;
  interval_lo?: number;
  interval_hi?: number;
  string_prefix?: string;
  string_suffix?: string;
  known_zero: number;
  known_one: number;
}

export interface AbstractBlockView {
  block_id: number;
  values: AbstractValueView[];
}

export interface AbstractInterpView {
  blocks: AbstractBlockView[];
}

// Symbolic Execution
export interface SymexValueView {
  ssa_value: number;
  var_name?: string;
  expression: string;
}

export interface PathConstraintView {
  block: number;
  condition: string;
  polarity: boolean;
}

export interface SymexView {
  values: SymexValueView[];
  path_constraints: PathConstraintView[];
  tainted_roots: number[];
}

// Call Graph
export interface CallGraphNodeView {
  id: number;
  name: string;
  file: string;
  lang: string;
  namespace: string;
  arity?: number;
}

export interface CallGraphEdgeView {
  source: number;
  target: number;
  call_site: string;
}

export interface CallGraphView {
  nodes: CallGraphNodeView[];
  edges: CallGraphEdgeView[];
  sccs: number[][];
  unresolved_count: number;
  ambiguous_count: number;
}

// Summaries
export interface ParamReturnView {
  param_index: number;
  transform: string;
}

export interface ParamSinkView {
  param_index: number;
  sink_caps: string[];
}

export interface SsaSummaryView {
  param_to_return: ParamReturnView[];
  param_to_sink: ParamSinkView[];
  source_caps: string[];
}

export interface FuncSummaryView {
  name: string;
  file_path: string;
  lang: string;
  namespace: string;
  arity?: number;
  param_count: number;
  source_caps: string[];
  sanitizer_caps: string[];
  sink_caps: string[];
  propagates_taint: boolean;
  propagating_params: number[];
  tainted_sink_params: number[];
  callees: string[];
  ssa_summary?: SsaSummaryView;
}
