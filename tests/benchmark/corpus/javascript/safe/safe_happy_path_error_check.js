// `cfg-error-fallthrough` previously fired on positive happy-path
// checks like `if (!data.error && Array.isArray(results))` because
// the rule's `mentions_err` test scanned the whole if-statement's
// taint.uses (including the body's `const err = ...` declaration)
// and ignored polarity.  This fixture pins two shapes:
//   1. `if (!data.error && other)` — compound condition with negated
//      err identifier; TRUE branch is the success path.
//   2. `if (!res.ok) { ... const err = await res.json().catch(...);
//      return ... }` — body mentions `err` but the condition itself
//      does not, so the rule must not fire.
async function loadPlaces() {
  const res = await fetch('/api/places');
  if (!res.ok) {
    if (res.status === 401) {
      return { error: 'unauthorized' };
    }
    const err = await res.json().catch(() => ({}));
    return { error: err.message || 'failed' };
  }
  const data = await res.json();
  if (data && !data.error && Array.isArray(data.results)) {
    return data.results;
  }
  return [];
}
