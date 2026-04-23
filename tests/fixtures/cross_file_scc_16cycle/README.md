# cross_file_scc_16cycle

A 16-function chain SCC across 16 files.  Same structure as
`cross_file_scc_8cycle`, scaled to 16 hops:

```
server.py --> step_a --> step_b --> ... --> step_o --> step_p
                  ^                                        |
                  +--------------- back edge --------------+
```

The sink (`subprocess.run(x, shell=True)`) is in `step_p.py`.

## Why this fixture exists

Stretches the SCC fix-point loop to a depth well beyond what an
earlier cap of 3 could handle, and near what `64` allows comfortably.
The observed iteration count is the single strongest evidence that the
production cap is sized correctly for deep chains.

## Expected convergence

- Lower bound: 16 iterations (one per chain hop).
- Upper bound: 32 iterations (2× monotone-refinement margin).

If this ever exceeds 32, the summary lattice is either non-monotone
(a bug) or is growing more slowly per iteration than it should.

## Relationship to the worklist

A dependency-driven worklist will eventually reduce per-iteration cost
without raising iteration count — i.e. the same 16 iterations, but
with each iteration re-analysing only the dirty subset of files.  This
fixture becomes the primary test case for proving that change.
