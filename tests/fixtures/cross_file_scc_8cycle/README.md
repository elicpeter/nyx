# cross_file_scc_8cycle

8-function chain SCC across 8 files.

```
server.py --> step_a --> step_b --> step_c --> step_d --> step_e --> step_f --> step_g --> step_h
                  ^                                                                           |
                  +----------------------- back edge -----------------------------------------+
```

The sink (`subprocess.run(x, shell=True)`) is in `step_h.py`. For the caller in `server.py` to see the transitive flow, the `param_to_sink` fact has to propagate backwards through seven cross-file summary-update iterations before `step_a`'s summary reflects the sink at `step_h`.

## What it tests

Broadens the existing 4-cycle fixture to exercise the SCC fix-point loop at a depth that any cap below 8 would silently truncate. Proves `SCC_FIXPOINT_SAFETY_CAP = 64` covers the >=8 range in practice. Once the worklist is dependency-driven, per-iteration cost should absorb the extra iterations without wall-clock regression.

## Expected convergence

- Lower bound: 8 iterations (one per chain hop).
- Upper bound: 16 iterations (2x monotone-refinement margin).

Above 16: summary-refinement regressed, or mutual-recursion detection started spuriously grouping more files.

Below 8: the chain is no longer serialised by Jacobi iteration. Either the pass-2 loop switched to Gauss-Seidel without updating this test, or summary extraction started including transitive callee summaries at pass-1 time.
