# CVE Hunt Session Log

One line per session, oldest first. Use this to rotate language coverage:
prefer the language that hasn't been touched in the most sessions.

```
YYYY-MM-DD HH:MM | <language> | added: N | recall fixed: M | deferred: K | notes: <one-line>
```

2026-04-27 15:50 | javascript | added: 0 | recall fixed: 1 (chained-call inner-gate) | deferred: 1 (CVE-2025-64430 needs cross-fn gated-sink param_to_sink + Promise-executor closure capture) | notes: chained-method `http.get(u,cb).on(...)` now classifies + new synthetic SSRF regression pair js-ssrf-003 / js-ssrf-safe-002
2026-04-28 06:30 | go | added: 1 (CVE-2023-3188 SSRF) | recall fixed: 2 (Go FILE_IO sinks os.Remove/WriteFile/RemoveAll + SSRF sink http.DefaultClient.Get/Post/Head/Do, Decode/Unmarshal as ContainerOp::Writeback) | deferred: 1 (CVE-2024-31450 Owncast path-trav needs json.Decoder writeback to propagate into field-cell channel for FieldProj) | notes: Go corpus 1→2 CVEs across cmdi+ssrf; +4 synthetic regression cases (go-ssrf-004 + safe pair, go-path-002 + safe pair); ContainerOp::Writeback variant added to engine domain
2026-04-28 09:50 | ruby | added: 1 (CVE-2020-8130 rake Kernel#open CMDI) | recall fixed: 1 (=-prefix exact-match sigil on label matchers + Ruby `=open` SHELL_ESCAPE rule, distinguishing bare Kernel#open from File.open / IO.open / URI.open) | deferred: 0 | notes: Ruby corpus 1→2 CVEs across deser+cmdi; +2 synthetic regression cases (ruby-cmdi-003 kernel-open + ruby-safe-009 file-namespaced); reusable engine primitive (`unpack_matcher` in src/labels/mod.rs) — any future bare-vs-namespaced label distinction can opt in via `=` prefix; rule-level F1 stays 0.998, Ruby slice F1 stays 1.000
2026-04-28 17:30 | go | added: 0 | recall fixed: 2 (Go `if init; cond {}` initializer lowering in CFG Kind::If; ContainerOp::Writeback → field-cell wildcard via new FieldId::ANY_FIELD sentinel) | deferred: 1 (CVE-2024-31450 still blocked — chained method-call SSA lowering is gap 3 of 3) | notes: budget burned on engine work, no new CVEs; +2 regression fixtures (go-path-003 / go-path-safe-003) pinning if-init taint flow; rule-level F1 0.998, Go slice F1 0.95→0.98
