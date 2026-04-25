# cross_file_alias_bounded_graph

## Purpose
Stability test for the bounded alias-graph promotion path. The fixture crosswires
five aliased containers so that the helper overflows the dense-alias budget and
falls back to the conservative "any arg taints any other arg" rule. The primary
guarantee is that the scanner **terminates** under overflow, not that a specific
finding fires.

## Expectations
- **required**: (none — terminating scan is the assertion)
- **forbidden**: (none — overflow promotion is conservative over-approximation;
  forbidden_findings would contradict the whole point of the fixture)
- **noise_budget**: max_total=20, max_high=10

## Why `noise_budget` stays
Because the dense-alias promotion deliberately over-approximates, the exact set
of findings can shift when the budget is tuned. The loose upper bound catches
any regression that explodes finding counts (a real failure mode if the
promotion logic is broken) without requiring lockstep alignment with whatever
happens to fire today. Dropping `noise_budget` here would remove the only
upper-bound check this fixture has.
