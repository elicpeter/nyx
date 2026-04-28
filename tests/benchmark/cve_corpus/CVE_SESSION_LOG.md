# CVE Hunt Session Log

One line per session, oldest first. Use this to rotate language coverage:
prefer the language that hasn't been touched in the most sessions.

```
YYYY-MM-DD HH:MM | <language> | added: N | recall fixed: M | deferred: K | notes: <one-line>
```

2026-04-27 15:50 | javascript | added: 0 | recall fixed: 1 (chained-call inner-gate) | deferred: 1 (CVE-2025-64430 needs cross-fn gated-sink param_to_sink + Promise-executor closure capture) | notes: chained-method `http.get(u,cb).on(...)` now classifies + new synthetic SSRF regression pair js-ssrf-003 / js-ssrf-safe-002
