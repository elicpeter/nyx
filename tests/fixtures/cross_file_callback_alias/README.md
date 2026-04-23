# cross_file_callback_alias — two-hop alias chain to cross-file sink

## Flow
`helpers.js` exports `dangerous`, a thin wrapper around
`child_process.exec`.  `app.js` imports it and resolves the call
through a two-hop local alias chain:

```js
const f = helpers.dangerous;
const g = f;
g(process.env.INPUT); // VULN (if the engine resolves the chain)
```

## Current engine behaviour (as of Phase 11)
**Known gap.** The scanner does not emit a `taint-unsanitised-flow`
finding for this pattern — the callback-binding resolver is
name-keyed and does not transitively walk assignments such as
`const g = f`.

`expectations.json` therefore lists **no required findings**; the
fixture exists purely as a pinned gap so a future improvement that
closes the alias-chain resolution has a concrete regression asset.

## Future work
Transitive alias resolution for local function bindings — detecting
`const g = f` / `g = f;` in the same function scope and folding the
alias into `callback_bindings` during lowering — would close this gap.
The structure is already in place:
`SsaTaintTransfer::callback_bindings` is consulted first in
`resolve_callee`, so the missing piece is the population step that
walks local alias assignments before summary extraction runs.
