// Real-repo shape from excalidraw's element manipulation libraries
// (`packages/element/src/binding.ts`, `frame.ts`, `duplicate.ts`,
// `DebugCanvas.tsx`).  In a pure data-manipulation function whose
// receiver is a JS built-in collection (`Map`, `Set`, `WeakMap`,
// `WeakSet`, `Array`) — either declared inline (`new Map()`),
// annotated directly (`m: Map<K, V>`), or aliased via a same-file
// `type X = Map<K, V>` — the call site is a container operation,
// not a data-layer read/mutation, and `js.auth.missing_ownership_check`
// must not flag.
//
// Closes the excalidraw FP cluster (66 → ~9 on
// `js.auth.missing_ownership_check`).  The fix lives at the deepest
// representable layer: SSA `TypeFacts::constructor_type` recognises
// `new Map()` / `new Set()` constructors as
// `TypeKind::LocalCollection`; `cfg::params::ts_type_to_local_collection`
// extends `classify_param_type_ts` so explicitly-typed params resolve
// to `LocalCollection` independent of NestJS decorator presence;
// `cfg::dto::collect_type_alias_local_collections` populates a
// per-file `TYPE_ALIAS_LC` set so same-file `type X = Map<...>`
// aliases also resolve.  The auth analyser already exempts
// `LocalCollection`-typed receivers via
// `auth_analysis::sink_class_for_type → InMemoryLocal`.

type ElementsMap = Map<string, { id: string; frameId?: string }>;
type IdMap = Map<string, string>;
type GroupSet = Set<string>;
type ElementArray = readonly { id: string }[];

interface BindingFix {
  elementId: string;
}

// ── 1. Direct Map<...> annotation on a parameter ────────────────────
function lookupBinding(
  binding: BindingFix,
  origIdToDuplicateId: Map<string, string>,
): string | undefined {
  return origIdToDuplicateId.get(binding.elementId);
}

// ── 2. Same-file `type X = Map<...>` alias ─────────────────────────
function debugRender(elementsMap: ElementsMap, id: string) {
  const bindable = elementsMap.get(id);
  if (!bindable) return null;
  return bindable;
}

// ── 3. Set / WeakMap / WeakSet annotation ──────────────────────────
function trackVisited(visited: Set<string>, key: string) {
  if (!visited.has(key)) {
    visited.add(key);
  }
  return visited.size;
}

function rememberElement(
  cache: WeakMap<object, string>,
  obj: object,
  v: string,
) {
  cache.set(obj, v);
  return cache.get(obj);
}

// ── 4. Array generics (`T[]`, `Array<T>`, `ReadonlyArray<T>`) ──────
function findItemArr(arr: { id: string }[], targetId: string) {
  return arr.find((x) => x.id === targetId);
}

function findItemReadonly(arr: ElementArray, targetId: string) {
  return arr.find((x) => x.id === targetId);
}

function findItemGeneric(arr: Array<string>, v: string) {
  return arr.find((x) => x === v);
}

// ── 5. Local `new Map()` / `new Set()` constructors ────────────────
function buildIndex(items: { id: string; v: string }[]) {
  const idx = new Map<string, string>();
  for (const it of items) {
    idx.set(it.id, it.v);
  }
  return idx.get(items[0]?.id ?? "");
}

// ── 6. Type-alias chain (alias of alias) ───────────────────────────
function aliasOfAlias(m: IdMap, k: string) {
  return m.get(k);
}

// ── 7. Set with `add` / `has` (mutation-side) ──────────────────────
function trackGroup(groups: GroupSet, g: string) {
  groups.add(g);
  return groups.has(g);
}
