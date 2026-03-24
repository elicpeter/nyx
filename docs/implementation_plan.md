# Nyx Serve — Implementation Plan

This plan breaks the full vision into phases, each scoped for one Claude Code session. Phases are ordered so that each builds on the previous — early phases establish the foundation, middle phases deliver the core product, and later phases add the differentiators that make Nyx special.

---

## Phase 1: Design System & App Shell

**Goal:** Replace the current minimal SPA shell with a real application frame. After this phase, the app feels like a product even though most pages are stubs.

### Backend
- No API changes needed yet

### Frontend
- **New CSS design system**: Design tokens (colors, spacing, typography, shadows, radii) as CSS variables. Light mode palette. Severity and confidence color scales. Component base styles (buttons, badges, cards, tables, inputs, dropdowns, tabs).
- **Left sidebar**: Persistent vertical nav with icons + labels for all 9 sections (Overview, Findings, Scans, Rules, Triage, Config, Explorer, Debug, Settings). Active state highlighting. Bottom utility section showing project path, engine version, and active scan indicator.
- **Top header bar**: Breadcrumb trail (context-sensitive), global search input (wired later), action buttons area (Start Scan, Export — wired later).
- **SPA router upgrade**: Hash-based or pushstate router supporting all routes from the vision (`/`, `/findings`, `/findings/:id`, `/scans`, `/scans/:id`, `/rules`, `/rules/:id`, `/triage`, `/config`, `/explorer`, `/debug`, `/debug/cfg`, `/debug/ssa`, `/debug/call-graph`, `/debug/taint`, `/settings`). Stub placeholder pages for sections not yet built, showing section title and "Coming soon" with a brief description.
- **Layout primitives**: Resizable split-pane CSS (used later), flex-based main panel, pane containers.
- **Favicon & branding**: Keep existing SVG favicon, refine if needed.

### Definition of done
- Opening the app shows the sidebar with all sections
- Clicking each section navigates to its route and shows the correct header
- Dashboard and Findings pages still render current functionality (migrated to new shell)
- Other pages show clean stubs
- Looks premium and calm, not like a prototype

---

## Phase 2: Findings List & Filtering

**Goal:** Transform the findings table from a basic list into a powerful, filterable, sortable data table that feels like a professional analysis tool.

### Backend
- Extend `GET /api/findings` query params: add `language`, `confidence`, `status`, `path_prefix`, `sort_by` options (severity, confidence, file, rule, line), `sort_dir`
- Add language detection info to `FindingView` (derive from file extension or stored lang)
- Add `confidence` field to `FindingView` if not already exposed properly
- Add `GET /api/findings/filters` endpoint returning available filter values (distinct severities, categories, rules, languages, files) for dynamic filter dropdowns

### Frontend
- **Rich data table**: Configurable columns (severity, confidence, rule, title, category, file, line, status). Column header click to sort. Alternating row shading. Compact density.
- **Filter bar**: Dropdowns for severity, confidence, category, language, rule, status. Text search input (file name, rule id, function, free text). "Only new" toggle. Clear all filters button. Filter counts in badges.
- **Pagination**: Page size selector (25/50/100). Page number display. Prev/Next/First/Last. Total count.
- **Row selection**: Checkbox per row. Select all on page. Bulk action bar appears when items selected (suppress, mark FP, export — actions wired in Phase 7).
- **Row click**: Navigates to finding detail (Phase 3 will make this open a side panel instead).
- **URL sync**: Filters and page stored in URL query string so links are shareable.

### Definition of done
- Findings page shows a professional data table
- All filter dimensions work and compose
- Sorting by any column works
- Pagination with configurable page size
- Keyboard: `/` focuses search

---

## Phase 3: Finding Detail Panel & Code Viewer

**Goal:** When a finding is selected, the findings page splits into a list + detail + code layout. This is where Nyx starts building trust.

### Backend
- Extend `GET /api/findings/:id` to return richer data:
  - `source_node`: { name, file, line, col } (the taint source)
  - `sink_node`: { name, file, line, col } (the sink call)
  - `sanitizer_status`: "none" | "bypassed" | "applied"
  - `rule_metadata`: { id, title, description, category, severity_default }
  - `evidence`: array of { type, description } fragments
  - `confidence_reasons`: array of string explanations
  - `related_findings`: array of { index, rule_id, file, line } for same-rule or same-file findings
- Add `GET /api/files` endpoint: accepts `path` and optional `start_line`/`end_line`, returns file content as array of lines with line numbers. Validates path is within scan root.

### Frontend
- **Three-pane layout**: Left 30% = findings list (narrower), Center 35% = finding detail, Right 35% = code viewer. Panes separated by draggable dividers (basic drag, refined in Phase 11).
- **Finding detail panel** with collapsible sections:
  - **Summary**: Title, severity badge, confidence badge, category, CWE, language, file:line, status.
  - **Why Nyx reported this**: Matched rule, source → sink description, sanitizer status, path length, interprocedural summary use. Rendered as structured cards, not raw JSON.
  - **Evidence**: Bullet list of evidence fragments (e.g., "`req.query.id` recognized as source", "call to `exec()` matched sink model").
  - **Confidence reasoning**: Explain how confidence was determined (direct path, no unresolved calls, etc.).
  - **Related findings**: Compact list of nearby/same-rule findings, clickable.
- **Code viewer**:
  - Fetch file content via `/api/files` endpoint.
  - Syntax highlighting using a lightweight approach (language-aware regex tokenizer or embedded highlight.js subset for top 10 languages).
  - Line numbers in gutter.
  - Highlighted source line (green left border).
  - Highlighted sink line (red left border).
  - Finding line highlighted with background color.
  - Scroll to finding line on load.
  - Surrounding function context (±30 lines minimum, ideally full function).

### Definition of done
- Clicking a finding in the list opens detail + code side by side
- Detail panel shows all sections with real data
- Code viewer shows the right file with syntax highlighting and finding markers
- Keyboard: `j/k` moves between findings, `enter` opens detail

---

## Phase 4: Flow Inspector & Explanation Engine

**Goal:** Build the biggest differentiator — a visual, step-by-step taint flow inspector that shows exactly how data flows from source to sink.

### Backend
- Extend finding data model with `flow_steps`: array of `{ step_number, description, file, line, col, code_snippet, node_type (source|propagation|call|return|sink), variable_name, function_name, is_cross_file }`. Populated from the taint engine's path data during scan.
- Modify scan pipeline to capture and store flow path information:
  - In `ssa_events_to_findings()`, attach the taint propagation chain to each `Finding`/`Diag`
  - Store source→sink path as structured data alongside the finding
- Add `GET /api/findings/:id/flow` endpoint returning the full flow with code snippets for each step.
- Add "Explain Finding" text generation: template-based, not AI — e.g., "Nyx found a path from user-controlled input `{source}` to the sink `{sink}` in `{file}`. The value passed through `{intermediaries}` without any configured sanitizer, so this may allow {category}."

### Frontend
- **Flow inspector panel** (replaces or tabs alongside code viewer):
  - Vertical step list, source at top, sink at bottom.
  - Each step is a card showing: step number, node type icon, variable name, function name, file:line, 3-line code snippet.
  - Cards are collapsible (show/hide snippet).
  - Color-coded by node type: green=source, blue=propagation, orange=call/return, red=sink, gray=sanitizer-check.
  - Cross-file transitions shown with a file-change indicator.
  - Click a step to scroll code viewer to that location.
- **"Why Nyx reported this" enhancement**: Use the template-based explanation text. Show as a readable paragraph at top of detail panel.
- **"Why not higher confidence?"**: For medium/low findings, show bullet list of uncertainty reasons (unresolved dispatch, unclear sanitizer, missing types).
- **View modes**: Toggle between "Flow" and "Code" in the right panel. Default to Flow when flow data exists.

### Definition of done
- Findings with taint paths show a step-by-step flow visualization
- Clicking a flow step scrolls the code viewer to the right location
- "Why Nyx reported this" shows a human-readable explanation
- Confidence reasoning is visible for every finding

---

## Phase 5: Scan Management & Real-time Progress

**Goal:** Make running and viewing scans feel like a first-class experience with real-time feedback, not just a spinner.

### Backend
- **Scan persistence**: Create `scans` table in SQLite storing scan metadata (id, status, root, started_at, finished_at, config_profile, engine_version, languages, files_scanned, files_skipped, finding_count, timing breakdown). Persist after scan completes.
- **Scan metrics collection**: During scan, collect and store metrics (AST nodes, CFG nodes, call edges, functions analyzed, summaries reused, taint edges explored, paths pruned, unresolved calls). Store in `scan_metrics` table.
- **Real-time progress**: Extend SSE events with `ScanProgress { job_id, stage, files_discovered, files_parsed, files_analyzed, current_file, elapsed_ms }`. Emit progress events periodically during scan (every 100 files or every 500ms).
- **Scan logs**: Capture structured log entries during scan (parsing progress, skipped files, warnings, analysis failures). Store in memory during scan, persist to `scan_logs` table.
- Extend `GET /api/scans/:id` to include metrics, timing breakdown, languages detected, files scanned/skipped.
- Add `GET /api/scans/:id/logs` endpoint.
- Add `GET /api/scans/:id/findings` endpoint (findings filtered to a specific scan).

### Frontend
- Remove the "New Scan" button from the dashboard that;s not in the header, also the "New Scan" button from the scan tab not in header.
- **New Scan dialog**: Modal with inputs for scan root, profile, languages, include/exclude paths, advanced options (debug mode, emit graphs). Start button. Links from header "Start Scan" button.
- **Scan progress view**: When scan is running, show real-time progress: stage indicator (discovering → parsing → analyzing → complete), file counts with progress bar, current file being processed, elapsed time, cancel button. Uses SSE events. No spinner — real data.
- **Scan detail page** (`/scans/:id`): Tabbed layout:
  - **Summary**: Metadata (id, time, duration, root, config, engine version), stat cards (files scanned, findings, languages).
  - **Findings**: Embedded findings list filtered to this scan.
  - **Logs**: Scrollable structured log viewer with level filtering (info/warn/error).
  - **Engine Metrics**: Grid of metric cards (AST nodes, CFG nodes, call edges, functions, summaries reused, taint edges, paths pruned, unresolved calls).
- **Scan list page** overhaul: Richer table with duration, finding count, delta from previous (new/fixed), status badges (running with pulse, completed, failed).

### Definition of done
- Starting a scan from the UI shows real-time progress with actual file counts
- Completed scans are persisted and browsable
- Scan detail page shows summary, findings, logs, and engine metrics
- Scan list shows history with useful metadata

---

## Phase 6: Scan Comparison

**Goal:** Enable comparing two scans to see what changed — critical for CI workflows and iterative engine development.

### Backend
- **Finding fingerprinting**: Generate stable fingerprints for findings based on (rule_id, file_path, sink_name, source_name, function_context). Fingerprints survive line shifts. Store in findings table.
- **Comparison API**: `GET /api/scans/compare?left=:id&right=:id` returns:
  - `new_findings`: in right but not left (by fingerprint)
  - `fixed_findings`: in left but not right
  - `unchanged_findings`: in both
  - `changed_findings`: same fingerprint but different severity/confidence/line
  - `summary`: counts for each category, severity deltas
- **Per-finding delta**: For changed findings, include old vs new values (line, confidence, severity).

### Frontend
- **Compare entry points**: "Compare" button on scan list (select two scans). "Compare with previous" on scan detail page. Route: `/scans/compare/:left/:right`.
- **Compare summary**: Top cards showing new/fixed/unchanged/changed counts. Severity breakdown delta chart (simple bar chart).
- **Compare views**: Tabs or toggles:
  - Grouped by status (new, fixed, changed, unchanged)
  - Grouped by rule
  - Grouped by file
  - Full diff table
- **Compare finding detail**: When opening a changed finding, show side-by-side: old location vs new, old confidence vs new, whether change is from code movement or analysis change.
- **Visual diff indicators**: Green = new, red = fixed, yellow = changed, gray = unchanged. Icons in finding rows.

### Definition of done
- Can select two scans and open compare view
- New/fixed/changed/unchanged findings are correctly identified
- Compare summary gives at-a-glance understanding of what changed
- Can drill into individual changed findings to see what's different

---

## Phase 7: Triage System

**Goal:** Add a complete triage workflow so findings have lifecycle state, not just a flat list.

### Backend
- **Triage state model**: SQLite `triage_states` table with columns: finding_fingerprint, state (open/investigating/false_positive/accepted_risk/suppressed/fixed), note, updated_at. Default state: Open.
- **Audit log**: SQLite `triage_audit_log` table: id, finding_fingerprint, action, previous_state, new_state, note, timestamp.
- **Triage API**:
  - `POST /api/triage` — Set state for one or more findings (bulk). Body: `{ fingerprints: [...], state: "...", note: "..." }`.
  - `GET /api/triage` — List triage states with filters (state, rule, file).
  - `GET /api/triage/audit` — Audit log with pagination.
  - `POST /api/triage/suppress` — Suppress by pattern: `{ by: "fingerprint"|"rule"|"rule_in_file"|"file", value: "...", note: "..." }`.
- **Integrate triage into findings**: `GET /api/findings` includes triage state per finding. Filter by triage state.

### Frontend
- **Triage controls in finding detail** (Phase 3 panel): Action buttons — Suppress, False Positive, Accepted Risk, Investigating, Fixed. Note input. Current state badge.
- **Bulk triage**: Select findings in list, bulk action bar: change state, add note, suppress by pattern/file/fingerprint.
- **Triage page** (`/triage`): Dedicated views:
  - All open highs
  - Recent suppressions
  - Accepted risks
  - Most suppressed rules (rules with highest suppression rate)
  - Stale findings (not touched in N scans)
- **Audit log view**: Table of triage actions with timestamp, action, target finding, old→new state, note. Filterable and paginated.

### Definition of done
- Every finding has a triage state visible in the list and detail
- Can change state individually and in bulk
- Triage page shows useful filtered views
- Audit log captures all triage actions
- Suppression by pattern/rule/file works

---

## Phase 8: Rules & Config Pages

**Goal:** Make rules inspectable and the analysis model configurable through the UI, not hidden in config files.

### Backend
- **Rules API** overhaul:
  - `GET /api/rules` — List all rules (built-in + custom) with metadata: id, title, language, category, severity, enabled, custom flag, finding count, suppression rate.
  - `GET /api/rules/:id` — Full rule detail: metadata, description, sources/sinks/sanitizers it relates to, example findings, confidence heuristics.
  - `POST /api/rules/:id/toggle` — Enable/disable rule.
  - `POST /api/rules/clone` — Clone built-in rule as custom.
  - Compute finding count and suppression rate per rule from scan data.
- **Config API** overhaul:
  - `GET /api/config/sources` — List all configured sources (built-in + custom) with language, matcher, cap.
  - `GET /api/config/sinks` — Same for sinks.
  - `GET /api/config/sanitizers` — Same for sanitizers.
  - `POST /api/config/sources`, `POST /api/config/sinks`, `POST /api/config/sanitizers` — Add custom entries.
  - `DELETE` variants for removal.
  - `GET /api/config/profiles` — List saved profiles.
  - `POST /api/config/profiles` — Save current config as named profile.
  - `POST /api/config/profiles/:name/activate` — Switch active profile.

### Frontend
- Remove the current settings page which has custom sanitizers and sinks and replace it with a coming soon stub
- **Rules page** (`/rules`): Two-column layout. Left: rule list with columns (id, title, language, category, enabled toggle, finding count, suppression rate, custom badge). Filters by language, category, custom-only. Right: selected rule detail — metadata, description, associated sources/sinks/sanitizers, triggered findings list (clickable), enable/disable toggle, clone-to-custom button.
- **Config page** (`/config`): Organized sections:
  - **General**: Scan root, include/exclude paths, enabled languages, max file size.
  - **Custom Sources**: Table with add/edit/remove. Fields: language, matcher pattern, cap type, notes.
  - **Custom Sinks**: Same structure.
  - **Custom Sanitizers**: Same structure.
  - **Confidence Tuning**: Display current heuristics with explanations. Sliders or toggles for tunable thresholds where applicable.
  - **Profiles**: List of saved profiles. Activate, edit, delete. Save current as new profile.

### Definition of done
- Rules page shows all rules with metadata and stats
- Can enable/disable rules, clone built-in to custom
- Config page provides structured editing for sources/sinks/sanitizers
- Profile save/load works
- Changes persist to disk and take effect on next scan

---

## Phase 9: Overview Page & Analytics

**Goal:** Replace the shallow dashboard with a real project-level analysis overview that makes Nyx feel like a security platform.

### Backend
- **Overview API**: `GET /api/overview` returning:
  - Total findings, new since last scan, fixed since last scan
  - High confidence rate
  - Triage coverage (% of findings with non-open state)
  - Latest scan duration
  - Findings by severity, category, language
  - Top affected files (top 10 by finding count)
  - Top affected directories
  - Top rules triggered
  - Rules with highest noise (high volume + high suppression rate)
  - Recent scans summary
- **Trends API**: `GET /api/overview/trends` — Scan-to-scan change in findings (requires multiple persisted scans). Returns array of { scan_id, timestamp, total, by_severity }.

### Frontend
- **Overview page** (`/`): Full redesign with widget grid:
  - **Top row**: Stat cards — Total findings, New since last scan, Fixed, High confidence rate, Triage coverage, Scan duration. Each with delta indicator (↑↓).
  - **Second row**: Charts — Findings over time (line/area chart, simple canvas or SVG rendering), Findings by severity (horizontal bar), Findings by category (horizontal bar), Findings by language (horizontal bar).
  - **Third row**: Tables — Top affected files, Top affected directories, Top rules triggered, Recent scans.
  - **Fourth row**: Insights — Recommended next actions (e.g., "12 High findings untriaged", "Rule XSS_REFLECTED has 80% suppression rate"), Rules generating most noise.
- **Conditional landing**: If no scans exist → show "Start your first scan" CTA. If scan just completed → highlight scan summary with CTA to findings. Otherwise → full overview.

### Definition of done
- Overview page shows real, useful analytics
- Charts render with actual scan data
- Hotspot and noise analysis visible
- Landing behavior adapts to scan state

---

## Phase 10: Explorer Page

**Goal:** Provide an IDE-like project browser where users can navigate files, see findings in context, and understand the project's security posture spatially.

### Backend
- **File tree API**: `GET /api/explorer/tree?path=` — Returns directory listing with metadata per entry: name, type (file/dir), language, finding_count, severity_max. Recursive expansion on demand.
- **Symbol API**: `GET /api/explorer/symbols?path=` — Returns functions/classes/methods extracted during scan for a given file. Includes: name, kind (function/class/method), line, finding_count.
- **File findings overlay**: `GET /api/explorer/findings?path=` — Findings for a specific file, ordered by line.

### Frontend
- **Explorer page** (`/explorer`): Three-column layout:
  - **Left**: File tree with expand/collapse. Finding count badges per file/directory. Severity indicators (colored dots). Click file to open in center pane.
  - **Center**: Code viewer (reuse from Phase 3). Full file view with finding markers in gutter. Click a marker to open finding detail in right pane.
  - **Right**: Analysis sidebar — File-level summary (findings count, severity breakdown), function/symbol list (from symbol API), findings list for selected file.
- **Explorer modes**: Toggle between file tree, symbol explorer, and hotspot view (files sorted by finding density).
- **Overlays**: Finding badges in tree, severity heat coloring on directories.

### Definition of done
- Can browse project file tree with finding counts visible
- Opening a file shows code with finding markers
- Can navigate from file → finding → detail seamlessly
- Symbol list shows functions/classes per file

---

## Phase 11: Debug Views

**Goal:** Expose engine internals — CFG, SSA, call graph, taint graph, state machines, heap analysis, constraint reasoning, abstract interpretation, symbolic execution, and SMT — for advanced users. This is where Nyx becomes truly special.

### Backend
- **CFG API**: `GET /api/debug/cfg?file=&function=` — Returns CFG for a function as graph JSON: nodes (basic blocks with statements, line ranges) and edges (branch type: true/false/unconditional/exception). Serialize from `Cfg` struct.
- **SSA API**: `GET /api/debug/ssa?file=&function=` — Returns SSA IR as structured data: blocks with `SsaOp` instructions, phi nodes, terminators, variable versions. Serialize from `SsaBody`.
- **Call graph API**: `GET /api/debug/call-graph?scope=file|project` — Returns call graph as nodes (functions with file, finding count) and edges (call relationships). Serialize from `CallGraph`.
- **Taint graph API**: `GET /api/debug/taint?file=&function=` — Returns taint propagation graph: nodes (variables/SSA values with taint status) and edges (propagation/sanitize/sink). Derived from `SsaTaintState` execution.
- **Summary API**: `GET /api/debug/summaries?function=` — Returns interprocedural summary for a function: source-to-return, arg-to-sink, sanitizer effects, SSA summary.
- **Function list API**: `GET /api/debug/functions?file=` — Returns list of functions available for debug inspection in a file.
- **State analysis API**: `GET /api/debug/state-analysis?file=&function=` — Returns state machine analysis for a function: states (identified abstract states), transitions (edges with trigger conditions), guards/auth gates on transitions, invalid transition reasoning (why a transition is rejected), reachability justification (why a transition was considered reachable), and path-to-violating-state (shortest path from initial state to a policy-violating state).
- **Heap/alias API**: `GET /api/debug/heap?file=&function=` — Returns heap analysis data: heap objects by allocation site (file, line, type), tracked fields per object, points-to sets (which pointers may/must point to which objects), must-alias vs may-alias pairs, and field-sensitive taint on object fields.
- **Constraint/path reasoning API**: `GET /api/debug/constraints?file=&function=` or `GET /api/debug/constraints?finding=<id>` — Returns path reasoning data: extracted predicates (type, variable, condition), accumulated path constraints along each path, infeasible branches pruned (branch location + contradicting constraint), type-based narrowing applied, and constraint contradictions detected.
- **Abstract interpretation API**: `GET /api/debug/abstract-interp?file=&function=` — Returns abstract interpretation state: interval facts per variable at each program point, string facts (prefix/suffix tracking), widened values at loop heads (pre- and post-widen), and sink suppressions justified by abstract facts (which sink, which variable, which fact proved safety).
- **Symbolic execution API**: `GET /api/debug/symex?file=&function=` or `GET /api/debug/symex?finding=<id>` — Returns symbolic execution data: symbolic values per variable (expression trees), explored paths (count and enumeration), feasible vs infeasible branch decisions, path budget and exhaustion status, and witness (concrete input assignment) if generated.
- **SMT reasoning API**: `GET /api/debug/smt?finding=<id>` — Returns SMT solver interaction data (only when SMT is enabled): whether SMT was invoked, which path/branch triggered it, result (SAT / UNSAT / UNKNOWN), timeout vs model found, and model-derived witness values if SAT.

### Frontend
- **Debug page** (`/debug`): Sub-navigation for CFG, SSA, Call Graph, Taint, Summaries, State Analysis, Heap/Alias, Constraints, Abstract Interp, Symbolic Execution, SMT.
- **Function selector**: Shared component — file picker + function dropdown. Used across all debug views.
- **CFG viewer** (`/debug/cfg`): Graph visualization using SVG/Canvas. Basic blocks as rectangles with statement text. Directed edges with branch labels. Highlight path relevant to a selected finding. Pan/zoom.
- **SSA viewer** (`/debug/ssa`): Block-based display showing SSA instructions per block. Phi nodes highlighted. Variable version chains. Mapping back to source lines.
- **Call graph viewer** (`/debug/call-graph`): Force-directed or hierarchical graph layout. Nodes = functions with finding badges. Edges = call relationships. Click node to see summary. Filter by file or namespace.
- **Taint graph viewer** (`/debug/taint`): Node types color-coded (source=green, propagation=blue, sanitizer=purple, sink=red). Edge labels for transforms. Filter to show only finding-relevant subgraph.
- **Summary explorer** (`/debug/summaries`): For a selected function, show its interprocedural summary: which params propagate, which hit sinks, sanitizer effects, confidence notes.
- **State analysis viewer** (`/debug/state-analysis`): State machine diagram showing identified states as nodes and transitions as labeled directed edges. Transitions display trigger conditions; guard/auth gate annotations shown inline. Invalid transitions rendered as dashed/red edges with rejection reason tooltip. Reachable transitions annotated with justification (why the engine believes this path is feasible). Violating-state paths highlighted — shortest path from initial state to the violation, with each step's reasoning visible on click. Filterable by state or transition type.
- **Heap / points-to / alias inspector** (`/debug/heap`): Structured table/tree view (graph visualization deferred). Heap objects listed by allocation site (file:line, inferred type). Each object expandable to show tracked fields with their taint status. Points-to sets displayed per pointer variable — list of target objects with must/may distinction. Must-alias and may-alias pairs shown in a deduplicated list with source locations. Field-sensitive taint on objects shown inline — which fields carry taint, from which origin.
- **Constraint / path reasoning viewer** (`/debug/constraints`): Accessible per-function or per-finding. Shows extracted predicates in a structured table (predicate kind, variable, condition expression). Accumulated path constraints displayed per-path as an ordered list. Infeasible branches highlighted with the contradicting constraint shown inline. Type-based narrowing shown as annotations (e.g., "x narrowed to int → FILE_IO suppressed"). Constraint contradictions called out explicitly with both conflicting constraints displayed side-by-side.
- **Abstract interpretation viewer** (`/debug/abstract-interp`): Per-function view showing variable facts at each program point. Interval facts displayed as `[lo, hi]` ranges in a variable × program-point grid. String facts shown as prefix/suffix pairs. Loop heads annotated with pre-widen and post-widen values to show where precision was traded for termination. Sink suppressions section: lists each suppressed sink with the justifying abstract fact (e.g., "SSRF suppressed: string prefix `https://safe.example.com/` locks host").
- **Symbolic execution viewer** (`/debug/symex`): Accessible per-function or per-finding. Shows symbolic values as collapsible expression trees. Path explorer lists all explored paths with feasible/infeasible status and branch decisions at each fork. Path count and budget displayed (e.g., "47 / 1000 paths explored"). Budget exhaustion clearly indicated when hit. Witness panel shows the concrete input assignment that reaches the sink, if generated — variable name → value mapping.
- **SMT reasoning panel** (`/debug/smt`): Only rendered when SMT is enabled (hidden or shows "SMT not enabled" otherwise). Per-finding view showing: whether SMT was invoked (and why — which branch/path triggered the query), solver result badge (SAT in green, UNSAT in red, UNKNOWN in yellow), timeout indication (duration + whether the solver timed out vs produced a result), and model-derived witness values if SAT (variable → concrete value table). Query details expandable for advanced users.

### Definition of done
- Can select a file and function, view its CFG as a graph
- SSA view shows instructions with variable versions
- Call graph renders project-wide or file-scoped
- Taint graph shows propagation for a function
- Summary explorer shows interprocedural summaries
- State analysis view renders state transitions, guards, invalid transition reasoning, reachability justification, and path to violating state
- Heap inspector shows allocation sites, points-to sets, must/may alias, and field-sensitive taint
- Constraint viewer shows predicates, path constraints, pruned branches, type narrowing, and contradictions for a function or finding
- Abstract interpretation view shows interval/string facts, widened values, and sink suppressions with justifying facts
- Symbolic execution view shows symbolic values, explored paths, feasibility, budget, and witness
- SMT panel shows invocation status, SAT/UNSAT/UNKNOWN result, timeout info, and model-derived witness values when SMT is enabled

---

## Phase 12: Advanced UX & Polish

**Goal:** Add the interaction design features that make the app feel like a real desktop-class tool — command palette, keyboard shortcuts, resizable panes, deep links, themes.

### Frontend
- **Command palette** (`Cmd+K` / `Ctrl+K`): Modal overlay with fuzzy search. Commands: Open file, Go to finding, Compare last scan, Run scan, Toggle code-only mode, Search rule, Open taint graph, Suppress finding, Navigate to any page. Recent commands. Keyboard-navigable.
- **Full keyboard shortcuts**:
  - `/` — Focus search
  - `j/k` — Move through findings/items
  - `Enter` — Open selected item
  - `[` / `]` — Previous/next finding
  - `g f` — Go to findings, `g s` — scans, `g r` — rules, `g o` — overview, `g d` — debug
  - `Escape` — Close panel/modal
  - `?` — Show keyboard shortcut help overlay
- **Resizable panes**: Proper drag-to-resize with cursor feedback and min/max constraints. Persist pane sizes in localStorage.
- **Deep linking**: Every meaningful state reflected in URL — finding detail, scan comparison, debug view for specific function, filter state. Browser back/forward works correctly.
- **Dark mode**: Full dark theme with CSS variable swap. Toggle in settings. Respect system preference. Proper contrast ratios for all severity/confidence colors.
- **Density modes**: Comfortable (default) and Compact. Toggle in settings. Affects table row height, padding, font sizes.
- **Settings page** (`/settings`): Theme toggle (light/dark/system), density mode, default page size, keyboard shortcut reference.
- A way to shutdown the server and close the browser tab automatically from inside the app.

### Definition of done
- Command palette opens with Cmd+K, supports fuzzy search across all commands
- All keyboard shortcuts work and are discoverable via `?`
- Panes are draggable with persisted sizes
- Dark mode looks polished, not just "inverted"
- URLs are deep-linkable for all major views

---

## Phase 13: Advanced Features & Nyx-Only Differentiators

**Goal:** Add the features that no other scanner has — the ones that make Nyx memorable and build deep trust with users.

### Backend
- **Explain Finding API**: `GET /api/findings/:id/explain` — Returns structured explanation with: plain-language summary, source description, path description, sink description, sanitizer status, confidence factors, uncertainty reasons.
- **"Why not higher confidence?" API**: Included in explain response — list of specific uncertainty factors (unresolved dispatch, unclear sanitizer semantics, branch feasibility, missing type info).
- **"Why not reported?" API**: `POST /api/debug/why-not-reported` — Accept a code snippet + rule + language, run analysis, return trace of why no finding was emitted (parser didn't match, path sanitized, no source detected, etc.). For rule testing.
- **Model coverage API**: `GET /api/debug/model-coverage?language=` — Returns which framework models are active, which major APIs are unresolved/unknown.
- **Path pruning data**: Include in finding flow data — which paths were pruned and why.

### Frontend
- **Explain Finding mode**: Button on finding detail that opens a clean, readable explanation panel. Not AI-generated fluff — structured, grounded, technical.
- **"Why not higher confidence?"**: Inline section in finding detail for medium/low findings. Shows specific uncertainty factors with icons.
- **Related findings**: Section in finding detail showing nearby findings (same file, same rule, same call chain). Click to navigate.
- **Hotspot analysis**: On overview page, heatmap-style view of directories/files by finding density. Clickable to drill down.
- **Rule noise analysis**: On overview and rules pages, highlight rules with high suppression rate or high false positive rate. Suggest rules to tune or disable.
- **Rule playground**: On rules page, paste a code snippet, select language and rule, run preview analysis, see matched source/sink/flow. Invaluable for rule authors.
- **Model coverage explorer**: On debug page, show which framework APIs are modeled and which are gaps. Helps users understand analysis limitations.
- **"Why not reported?" testing**: On debug page, paste code + select rule, see step-by-step trace of why no finding was emitted. Essential for rule development.

### Definition of done
- Explain Finding produces a clear, grounded explanation for any finding
- Confidence reasoning shows specific uncertainty factors
- Rule playground can run analysis on pasted code
- Model coverage is browsable
- "Why not reported?" works for debugging missing findings

---

## Summary

| Phase | Focus | Key Deliverable |
|-------|-------|-----------------|
| 1 | App Shell & Design System | Real application frame with sidebar, header, routing |
| 2 | Findings List & Filtering | Professional filterable, sortable data table |
| 3 | Finding Detail & Code Viewer | Three-pane layout with detail sections and syntax-highlighted code |
| 4 | Flow Inspector & Explanations | Step-by-step taint flow visualization and "Why Nyx reported this" |
| 5 | Scan Management & Progress | Real-time scan progress, persistence, scan detail page |
| 6 | Scan Comparison | Compare two scans, see new/fixed/changed findings |
| 7 | Triage System | Finding lifecycle states, bulk actions, audit log |
| 8 | Rules & Config Pages | Rule browser, config editor, profiles |
| 9 | Overview & Analytics | Rich dashboard with charts, hotspots, noise analysis |
| 10 | Explorer Page | IDE-like file browser with finding overlays |
| 11 | Debug Views | CFG, SSA, call graph, taint graph visualization |
| 12 | Advanced UX & Polish | Command palette, keyboard shortcuts, dark mode, deep links |
| 13 | Advanced Differentiators | Explain finding, rule playground, model coverage, "why not reported?" |

After Phase 13, Nyx Serve is the full vision: a premium, deeply inspectable, local-first security analysis workspace.
