# cross_file_scc_8cycle

An 8-function chain SCC across 8 files:

```
server.py --> step_a --> step_b --> step_c --> step_d --> step_e --> step_f --> step_g --> step_h
                  ^                                                                           |
                  +----------------------- back edge -----------------------------------------+
```

The sink (`subprocess.run(x, shell=True)`) is in `step_h.py`.  For the
caller in `server.py` to see the transitive flow, the `param_to_sink`
fact has to propagate backwards through seven cross-file summary-update
iterations before `step_a`'s summary reflects the sink at `step_h`.

## Why this fixture exists

Phase-E broadens the existing 4-cycle fixture to exercise the SCC
fix-point loop at a depth that would have been silently truncated
under *any* pre-Phase-E cap below 8.  This proves the current
`SCC_FIXPOINT_SAFETY_CAP = 64` actually covers the ≥8 range in
practice (and, once Phase B lands, that the worklist reduces
per-iteration cost enough to absorb the extra iterations without
wall-clock regression).

## Expected convergence

- Lower bound: 8 iterations (one per chain hop).
- Upper bound: 16 iterations (allows a 2× monotone-refinement margin).

A rise above 16 means summary-refinement regressed or mutual-recursion
detection started spuriously grouping more files.

A drop below 8 means the chain is no longer serialised by Jacobi
iteration — either the pass-2 loop switched to Gauss-Seidel without
updating this test, or summary extraction started including
transitive callee summaries at pass-1 time.
