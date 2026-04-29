// CVE Hunt Session 4 regression — Go `if init; cond` taint flow.
// Tree-sitter exposes Go's `if x := f(...); x != nil { ... }` initializer
// under the `initializer` field of the `if_statement` node. The CFG
// builder's `Kind::If` arm previously skipped the init subtree entirely —
// any side-effect-bearing call inside the init was invisible to taint
// analysis, so flows like `if name := r.URL.Query().Get("p"); name != ""`
// followed by `os.Remove(filepath.Join(_, name))` looked clean to the
// engine even though the source-to-sink chain was right there.
//
// Owncast CVE-2024-31450 has this exact shape (`if err :=
// json.NewDecoder(r.Body).Decode(emoji); err != nil`) but the full chain
// also depends on chained-method-call lowering (the receiver of `Decode`
// is the result of `NewDecoder(r.Body)`, which Go's CFG currently merges
// into a single Call with text `"json.NewDecoder(r.Body).Decode"` and no
// separate inner-call SSA value). This fixture exercises the simpler
// init-only variant where the source is direct, isolating the if-init
// CFG fix from the chained-call gap.
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if name := r.URL.Query().Get("name"); name != "" {
		target := filepath.Join("data/uploads", name)
		os.Remove(target)
	}
	_ = w
}
