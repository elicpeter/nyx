# cross_file_callback_alias

Two-hop alias chain to a cross-file sink.

## Flow

`helpers.js` exports `dangerous`, a thin wrapper around `child_process.exec`. `app.js` imports it and resolves the call through a two-hop local alias chain:

```js
const f = helpers.dangerous;
const g = f;
g(process.env.INPUT); // VULN (if the engine resolves the chain)
```

## Status

Known gap. The scanner does not emit a `taint-unsanitised-flow` finding for this pattern. The callback-binding resolver is name-keyed and does not transitively walk assignments like `const g = f`.

`expectations.json` lists no required findings. The fixture is a pinned gap so a future improvement that closes the alias-chain resolution has a concrete regression asset.

## What would close it

Transitive alias resolution for local function bindings: detect `const g = f` / `g = f;` in the same function scope and fold the alias into `callback_bindings` during lowering. The hook is already there. `SsaTaintTransfer::callback_bindings` is consulted first in `resolve_callee`. Missing piece is the population step that walks local alias assignments before summary extraction runs.
