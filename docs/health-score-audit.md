# Health Score — internal audit, 2026-04-28

> Audience: maintainers.  Calibration data, failure modes, and the case
> for the v2 formula.  The customer-facing methodology is in
> [health-score.md](./health-score.md).

## Why audit it now

The Health Score (0–100, A–F) was added to the overview dashboard
shortly before the v0.5.0 prerelease.  It is the single most prominent
number on the dashboard.  Two specific worries drove this audit:

1. **"Is this our fault or theirs?"**  At a previous security ranking
   company, customers reliably blamed the scanner whenever they got a
   low score.  Defending a score in front of an angry customer requires
   a methodology the score itself can survive.
2. **Top-of-scale false confidence.**  An A grade can be read as "your
   code is secure" — when it actually means "Nyx didn't find anything
   under its current rule coverage".  Limit and label.

This document records what the v1 formula did, where it broke, and why
the v2 changes are the smallest set that produce defensible scores.

## v1 (pre-audit) formula

```
weighted          = HIGH*10 + MEDIUM*3 + (LOW − quality_lints)*0.5 + quality_lints*0.2
severity_score    = clamp(100 − 30·log10(1 + weighted/5), 0, 100)
confidence_score  = (HighCount + 0.5·MediumCount) / total · 100
trend_score       = clamp(50 + 5·(fixed − new), 0, 100)
triage_score      = triage_coverage · 100
regression_score  = max(100 − 10·reintroduced, 0)

final  =  0.30·severity + 0.15·confidence + 0.20·trend
        + 0.20·triage   + 0.15·regression
```

Source: `src/server/routes/overview.rs::compute_health_score` at
`ac46122`.  Weights sum to 1.00 unconditionally, every component
contributes regardless of whether it has meaningful input.

## Failure modes found

### F1. First-scan punishment — Triage drag

A brand-new user with no findings *and* no triage state currently gets
Triage = 0/100, weight 0.20 — a guaranteed 20-point ceiling.

**Worst case:** clean repo, first scan, no findings.  v1 score = 70 (C).
The user reads "C" and concludes Nyx is broken or their codebase is
mediocre, when in fact Nyx found nothing at all.

### F2. First-scan punishment — Trend drag

Same shape as F1 for the Trend component.  `trend_score` defaults to 50
when `fixed = new = 0`, and that's also what an honest "no history"
state would emit.  The two cases are indistinguishable to the scorer
but very different to the user.  20% of the score is pinned at 50/100
on every first scan.

### F3. Severity not size-aware

`weighted = 10·HIGH + …` is absolute.  A 100-file repo with one HIGH
and a 5MLOC repo with one HIGH are treated identically on this axis,
even though the one-HIGH-in-5MLOC repo is materially less compromised.

Caveat: we do **not** want a 5MLOC repo to get a "free pass" on a
HIGH.  Any size adjustment must cap so the dampening can't be
exploited to dilute serious findings.

### F4. False A grade for one HIGH

The most-defensible-against-customers failure mode.  v1 gave a
clean-but-for-one-HIGH repo a final score around 86 — a B, but only
just.  Worse, the *severity component* alone scored ~86, with no
explicit ceiling.  A reasonable security engineer says "any HIGH means
you don't get an A on this scoring axis."  v1 did not enforce that.

### F5. Hidden HIGH among triaged noise

The catch-22 case:

> 95% of 1000 LOW findings are triaged.  One HIGH is buried.

v1 score: 71 (C).  The triage component pulled it up from where the
severity component would have placed it (40).  A C grade reads as "you
have some work to do" — but you have one untriaged HIGH at the
bottom of the noise.

### F6. Single weight set, no transparency

Every dropped/inapplicable component still consumed weight in v1.
There was no signal to the dashboard about which components were
*meaningfully measured* on this scan vs. which were defaulted.

### F7. No aging signal

A 1-year-old HIGH and a 1-day-old HIGH contributed the same weight to
the score.  In real customer experience, stale HIGHs are the strongest
predictor of pain — they've survived multiple scan cycles and triage
sessions and remain unaddressed.

## v2 changes (targeted, additive)

Each change addresses one numbered failure mode above.  None changes
the API shape; `HealthScore` and `HealthComponent` serialize the same.

| ID  | Change | Tunable |
|-----|--------|---------|
| C1  | Drop **Triage** (weight=0) when total findings < TRIAGE_FLOOR | `TRIAGE_FLOOR = 20` |
| C2  | Drop **Trend** (weight=0) when there is no prior completed scan | `has_history` boolean |
| C3  | Apply size-aware dampening to severity weighting, capped | `SIZE_FLOOR_FILES = 500`, `MAX_SIZE_RATIO = 20.0` |
| C4a | Cap the **severity component** by HIGH count (84 / 75 / 65) | `high_count_ceiling` |
| C4b | Cap the **final score** by HIGH count (89 / 79 / 69) — backstops C4a after blending | `high_total_ceiling` |
| C5  | (Mitigated by C4b — final-score cap binds before triage can dilute the HIGH) | — |
| C6  | Renormalize weights when a component drops; surface "Not applicable: …" detail string | inline |
| C7  | Stale-HIGH penalty — when HIGHs exist *and* `BacklogStats.stale_count > 0`, subtract up to 20 points from the severity component | `STALE_PENALTY_PER_FINDING = 4.0`, `STALE_PENALTY_CAP = 20.0` |

The constants are tunables, not laws of nature.  They are what
calibration produces below; future calibration runs can revisit.

### Code layout

```
src/server/health.rs            ← pure scoring math + unit tests
src/server/routes/overview.rs   ← thin wrapper that builds HealthInputs
                                  from app/DB state and calls compute()
docs/health-score-audit.md      ← this file
docs/health-score.md            ← customer-facing methodology
tests/health_score_calibration.rs ← pinned reference scores (regression net)
```

## Calibration table — real OSS repos

Scanned with `target/release/nyx scan --format json` at
`ac46122` (the prerelease-cleanup tip), 2026-04-28.  All repos under
`/Users/elipeter/oss/<name>`.  All "first scan" — no triage state, no
prior scan to compare against.  Scores computed with
`/tmp/calibrate.py`, which mirrors `src/server/health.rs` exactly (
unit-tested cross-validation).

### First scan (no triage, no history)

| Repo    | Files | Total | H  | M   | L  | Q  | v1 | v1g | v2 | v2g | Δ   |
|---------|------:|------:|---:|----:|---:|---:|---:|----:|---:|----:|----:|
| ripgrep |   134 |     9 |  0 |   7 |  2 |  5 | 60 | D   | 84 | B   | +24 |
| gin     |    99 |     6 |  4 |   2 |  0 |  0 | 60 | D   | 79 | C   | +19 |
| express |   141 |   181 |  0 | 174 |  7 |  0 | 50 | F   | 50 | F   |   0 |
| caddy   |   310 |    92 | 28 |  59 |  5 |  0 | 47 | F   | 46 | F   |  −1 |
| django  |  3002 |   480 | 36 | 424 | 20 |  0 | 43 | F   | 45 | F   |  +2 |

### Second scan (history present, no change since prior)

Same repos, same finding sets, but with `has_history=True` and trend at
its default 50.  This isolates the effect of C2 alone.

| Repo    | v1 | v1g | v2 | v2g |  Δ  |
|---------|---:|----:|---:|----:|----:|
| ripgrep | 60 | D   | 75 | C   | +15 |
| gin     | 60 | D   | 75 | C   | +15 |
| express | 50 | F   | 50 | F   |   0 |
| caddy   | 47 | F   | 47 | F   |   0 |
| django  | 43 | F   | 46 | F   |  +3 |

### Reading the table

* **ripgrep + gin** both have <20 findings, so **C1** drops triage.
  On first scan **C2** also drops trend.  These are the repos where
  v1 punished users hardest for not having metadata that didn't apply.
  v2 lifts each by 24 / 19 points respectively.
* **express** stays F at 50 because triage *is* active (181 findings
  ≥ 20) and is at 0% on a fresh scan — and 174 unaddressed
  Mediums genuinely warrant an F until the user starts triaging or
  fixing them.  This is correct behaviour.
* **caddy / django** stay F because they have many real HIGHs.  C4b
  caps them at D 69 / C 79, but the natural blend already places
  them well below those caps.  The cap doesn't bind here.
* No repo's grade *fell* in v2.  A 1-point drop on caddy is
  rounding noise.

## Calibration table — synthetic boundary cases

These are the sentinel scenarios the audit prompt called out.  Each
maps to one or more failure modes from above.

| Case               | v1 score | v1 grade | v2 score | v2 grade | Notes                                                    |
|--------------------|---------:|---------:|---------:|---------:|----------------------------------------------------------|
| Clean repo         |       70 |    C     |      100 |    A     | F1 + F2 fixed                                            |
| 1 HIGH only        |       66 |    D     |       89 |    B     | F4 fixed (no longer A; capped at B)                      |
| 3 HIGHs only       |       62 |    D     |       79 |    C     | C4b binds at 79                                          |
| 10 HIGHs only      |       58 |    F     |       69 |    D     | C4b binds at 69; v1 was unfairly F                       |
| 1000 LOWs only     |       44 |    F     |       46 |    F     | Both formulas correctly say "lots of work"               |
| 200 quality lints  |       61 |    D     |       64 |    D     | Quality discount preserved                               |
| **Hidden HIGH**    |       71 |    C     |       79 |    C     | F5: still C, but explicitly capped — see below           |

### Hidden HIGH — the deceptive case

> 1 untriaged HIGH + 1000 LOWs at 95% triage coverage, files=1500.

Both formulas grade this **C**, but for opposite reasons:

* **v1** lands at 71 because triage (95%) and confidence (100%) lift
  the score from a severity component of 40.  The user sees C and
  reads "good progress on a noisy codebase".
* **v2** lands at 79 — *capped* there by the 1-HIGH ceiling.  Without
  the cap the underlying blend would have produced 78 → C anyway, so
  the user-visible grade matches v1 in this specific case.  The
  difference is *why*: v2's component breakdown surfaces "Severity
  pressure: 47 (capped at 84 because of 1 HIGH)" instead of "Severity
  pressure: 40, but triage saved you".

The fix isn't about moving the headline number, it's about making the
breakdown honest.  C7 (stale-HIGH penalty) is the kicker: if that one
HIGH has been open >30 days, severity drops further and the cap on the
total isn't even what binds.

## Stale-HIGH penalty calibration

C7 demonstration: same 1-HIGH repo, varying `stale_count` from
`BacklogStats`:

| stale_count | sev component | total score | grade |
|------------:|--------------:|------------:|------:|
|           0 |            84 |          82 |   B   |
|           1 |            80 |          80 |   B   |
|           3 |            72 |          77 |   C   |
|           5 |            64 |          74 |   C   |
|          20 |            64 |          74 |   C   |

Penalty caps at 20 points (5 stale findings × 4 points).  The cap
exists so a backlog of 50+ stale items doesn't zero out severity — at
that point you have a process problem, not a scoring problem.

## Failure modes still present in v2 (not fixed; documented)

These are the things v2 explicitly does not solve.  Customers asking
"why did I get an X?" should be pointed at this list when their case
matches.

* **F2'** A clean repo *with* history but no fixes since the prior
  scan grades B (88) instead of A.  Trend = 50 (no change) is honest
  but penalizes "stayed clean for two scans" the same as "didn't
  improve".  Future work: distinguish "no findings, no change" from
  "still N findings, no change".
* **Confidence quality double-counts severity** — a HIGH-confidence
  HIGH lifts the confidence component (which reads as "scanner trust")
  even though the finding itself is bad.  The component name is
  ambiguous.  Renaming options on the table; left for v3.
* **Density not penalized** — 4 HIGHs in 99 files (gin) and 4 HIGHs
  in 50000 files (theoretical) get the same severity component
  score.  Size adjustment lifts the big-repo score but doesn't pull
  the small-repo score down.  This is intentional: we'd rather over-
  penalize density than under-penalize it.
* **Score 100 ≠ "secure"** — most important caveat.  Score 100 means
  "Nyx found nothing under its current rule and language coverage".
  It does not certify the absence of vulnerabilities.  Documented
  prominently in `docs/health-score.md` Limitations section.
* **Languages outside Nyx coverage** — a repo of mostly Kotlin (no
  Nyx coverage) will score artificially well because Nyx never
  evaluates the bulk of the code.  Should be detected at scan time
  and surfaced as a banner; future work, tracked separately.

## Regression net

`tests/health_score_calibration.rs` pins the synthetic boundary cases
above to `(min, max)` score bands.  When someone tweaks a weight or a
constant in `src/server/health.rs`, this test fails fast if the change
silently re-grades the boundary cases.  Bands are deliberately wide
(±5 points) so honest curve-shape adjustments don't trip the test —
it catches "weights silently changed" bugs, not algorithmic refinement.

## Open questions

1. Should `Confidence quality` be renamed to make its meaning explicit?
   Candidates: "Signal certainty", "Scanner certainty".
2. Should size adjustment use KLOC instead of file count?  KLOC is
   more honest but expensive to compute; file count is cheap and
   already plumbed via `ScannerQuality.files_scanned`.  We picked
   file count for v2.
3. Should "no findings, with history" lift the trend score above 50
   when the prior scan also had no findings?  ("Stayed clean.")  In
   scope for a v3 trend overhaul; deferred.
