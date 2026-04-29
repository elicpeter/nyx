// FP guard for `js.auth.missing_ownership_check` — JS built-in
// container receivers must not be classified as data-layer sinks.
// See `tests/benchmark/corpus/typescript/auth/safe_local_collection_receiver.ts`
// for the full real-repo distillation.

type ElementsMap = Map<string, { id: string }>;

function fromAlias(elementsMap: ElementsMap, id: string) {
  return elementsMap.get(id);
}

function fromDirectGeneric(m: Map<string, string>, k: string) {
  return m.get(k);
}

function fromArrayShorthand(arr: { id: string }[], targetId: string) {
  return arr.find((x) => x.id === targetId);
}

function fromLocalConstructor() {
  const cache = new Map<string, string>();
  cache.set("a", "x");
  return cache.get("a");
}

function fromSet(visited: Set<string>, k: string) {
  if (!visited.has(k)) {
    visited.add(k);
  }
  return visited.size;
}
