# Health Score — methodology

The Health Score on the overview dashboard is a 0–100 rollup that
captures how much pending security work Nyx sees in your repo, how
fresh that work is, and whether your team is keeping up with it.  This
page is the methodology behind the score: how it is computed, what it
deliberately does *not* measure, and what to look at when you disagree
with the grade.

If you got a low grade and you're here to understand why, jump to
[How is this calculated for my repo?](#how-is-this-calculated-for-my-repo)
first.

## What the score measures

The score answers one specific question:

> Given everything Nyx has currently found in this repository, and the
> trend over recent scans, how much active security debt does this
> repo carry?

It is a *Nyx-finding-pressure* metric, not an absolute statement about
your repository's security posture.  Read the
[Limitations](#limitations) section before relying on the headline
number.

## The five components

The final score blends five components.  Each component is a
standalone 0–100 sub-score with a transparent breakdown shown in the
dashboard tooltip.

| Component             | Default weight | What it measures                                                                |
|-----------------------|---------------:|---------------------------------------------------------------------------------|
| Severity pressure     |          30 % | Volume and seriousness of findings, size-aware                                  |
| Confidence quality    |          15 % | What fraction of findings the scanner is confident about                        |
| Trend                 |          20 % | Net direction since the previous scan (improving / regressing)                  |
| Triage coverage       |          20 % | Fraction of findings that have been moved out of the default open state        |
| Regression resistance |          15 % | Penalty for findings that were once fixed and have re-appeared                  |

Two of the weights (Trend and Triage coverage) drop to 0 % when the
component cannot be measured meaningfully — for example, on your very
first scan, or in a repo with too few findings to have a triage
posture.  When that happens, the breakdown shows
"Not applicable: …" and the remaining weights are renormalized so a
dropped component doesn't silently drag the score down.

### 1. Severity pressure (30 %)

The most heavily weighted component.  It captures both *how many*
findings exist and *how serious they are*, with diminishing returns
so a sea of low-severity quality lints can't dominate the score.

#### Step 1 — weighted point total

```
weighted = HIGH × 10
         + MEDIUM × 3
         + (LOW − quality_lints) × 0.5
         + quality_lints × 0.2
```

`quality_lints` are LOW-severity findings whose rule ID lives in a
`*.quality.*` family — code-hygiene issues like Rust's
`rs.quality.unwrap`.  They count, but at 60 % of the weight of a
security LOW.

#### Step 2 — size-aware dampening

A 5-million-line monorepo with one HIGH carries less marginal risk per
HIGH than a 5,000-line library with one HIGH.  We dampen severity
pressure for large repos, but cap the dampening so a huge repo can't
dilute serious findings:

```
size_factor      = min(20, max(1, files_scanned / 500)) ^ 0.5
weighted_adjust  = weighted / size_factor
```

The cap at √20 ≈ 4.47× hits at roughly 10,000 scanned files.  A
50,000-file monorepo gets the same dampening as a 10,000-file repo —
no further free pass.  Repos with fewer than 500 scanned files get
no size adjustment at all.

#### Step 3 — log curve

The adjusted weighted total is mapped to a 0–100 score on a log curve:

```
raw_severity = 100 − 30 × log10(1 + weighted_adjust / 5)
```

This stays sensitive at the low end (the first few HIGHs really hurt)
and degrades gracefully at the high end (the 100th HIGH costs about
the same as the 99th).  Reference points:

| weighted_adjust | raw_severity | Reads as       |
|----------------:|-------------:|----------------|
|               0 |          100 | nothing pending |
|              10 |           86 | a few findings |
|              50 |           69 | meaningful work |
|             200 |           46 | a lot of work  |
|             600 |           29 | F territory    |

#### Step 4 — HIGH-count ceiling on the component

Independent of the math above, having any unaddressed HIGH puts a hard
ceiling on the severity component:

| HIGH count | Severity component capped at |
|-----------:|-----------------------------:|
|          0 |                          100 |
|        1–2 |                           84 |
|        3–5 |                           75 |
|         6+ |                           65 |

This expresses the security-engineer prior that "any HIGH means you
don't get an A on severity, period."  The cap binds even when the log
curve would have produced a higher number.

#### Step 5 — stale-HIGH penalty

If the repo has at least one HIGH and the backlog contains findings
older than 30 days (`stale_count > 0`), severity drops further:

```
stale_penalty = min(20, stale_count × 4)
severity      = max(0, severity_after_cap − stale_penalty)
```

A stale HIGH is the strongest predictor of pain in real customer
experience.  A fresh HIGH says "we just learned about this".  A 90-
day-old HIGH says "we keep punting".

#### Worked example

> A medium Rust repo with 3 HIGH, 12 MEDIUM, 4 LOW, 6 quality lints,
> 850 files scanned, 2 stale findings.

```
weighted          = 30 + 36 + (4-4)*0.5 + 6*0.2 + 4*0.5*0(*) = 30 + 36 + 0 + 1.2 = 67.2
                    (* the 4 LOWs are entirely covered by the 6 quality lints,
                       so security_low = 0 and quality contributes 4 of the 6 at 0.2)
size_factor       = sqrt(min(20, 850/500))     = sqrt(1.7) ≈ 1.30
weighted_adjust   = 67.2 / 1.30                = 51.7
raw_severity      = 100 − 30·log10(1 + 51.7/5) = 100 − 30·log10(11.3) ≈ 68.4
high_cap (3-5)    = 75
after_cap         = min(68.4, 75)              = 68.4
stale_penalty     = min(20, 2·4)               = 8
final severity    = max(0, 68.4 − 8)           = 60.4 → 60
```

### 2. Confidence quality (15 %)

What fraction of the findings does Nyx have high confidence in?
Higher means the scanner is giving clear, actionable signals; lower
means a lot of "the scanner thinks this might be a problem" entries.

```
confidence = (HighConfCount + 0.5 × MediumConfCount) / total × 100
```

Findings without a confidence label do not contribute.  An empty
findings list scores 100 (no signals to be uncertain about).

This component **is not** a measure of severity — a repo with
HIGH-confidence HIGH findings will score well on Confidence quality
and badly on Severity pressure.  That's the point: the two components
are orthogonal.  The confidence component measures *signal quality*.

### 3. Trend (20 %)

Net direction of total findings since the previous completed scan.

```
trend = clamp(50 + 5 × (fixed_since_last − new_since_last), 0, 100)
```

Each net fix moves you up 5 points; each net new finding moves you
down 5.  A scan with no change holds you at 50 (neither improving nor
regressing).

**On your first scan**, this component is dropped entirely
(weight = 0) because there is no prior scan to compare against.  The
breakdown will read "Not applicable: no prior scan to compare
against".  Re-scan to populate the trend.

### 4. Triage coverage (20 %)

What fraction of findings have been moved out of the default
"open" state — to investigating, false_positive, accepted_risk,
suppressed, or fixed?

```
triage = triage_coverage × 100
```

A finding counts as triaged if it has any non-open triage state,
*or* if a suppression rule (by fingerprint, rule id,
rule-in-file, or path) matches it.

**When total findings < 20**, this component is dropped entirely
(weight = 0).  It would be unfair to penalize a fresh user 20 % of
their score for not having gone through the triage flow on a handful
of findings.  The breakdown will read "Not applicable: only N
finding(s) (need ≥20 to evaluate)".

### 5. Regression resistance (15 %)

Penalty for findings that previously appeared in a scan, were absent
in a later scan, and are now back.

```
regression = max(0, 100 − 10 × reintroduced_count)
```

`reintroduced_count` is the count of findings whose fingerprint was
present in some past scan, was *absent* in the immediately-preceding
scan, and is present in the current scan.  Each reintroduced finding
costs 10 points; the floor is 0.

A fresh repo with no regressions scores 100 here.

## Severity weighting and quality discount

A few worked numbers showing how the weighting plays out across
common shapes of finding inventory.  All assume the size factor is
1.0 (a small repo) and no stale findings, so you can read the
severity component directly from the log curve.

| Inventory                                   | weighted | Severity component (raw) | After HIGH cap   |
|---------------------------------------------|---------:|-------------------------:|------------------|
| 0 findings                                  |        0 |                      100 | 100 (no cap)     |
| 1 HIGH                                      |       10 |                       86 | 84 (1-2 HIGH)    |
| 1 HIGH + 5 MEDIUM                           |       25 |                       77 | 77 (≤84)         |
| 5 HIGH                                      |       50 |                       69 | 69 (≤75)         |
| 10 HIGH                                     |      100 |                       60 | 60 (≤65)         |
| 100 MEDIUM                                  |      300 |                       45 | 45 (no cap)      |
| 100 LOW (security)                          |       50 |                       69 | 69 (no cap)      |
| 100 quality lints                           |       20 |                       72 | 72 (no cap)      |
| 1 HIGH + 100 LOW + 100 quality              |       80 |                       64 | 64 (≤84)         |

## Letter-grade thresholds

| Score range | Grade |
|-------------|-------|
| 90 – 100    |   A   |
| 80 – 89     |   B   |
| 70 – 79     |   C   |
| 60 – 69     |   D   |
| 0 – 59      |   F   |

## How to improve your score

| Component             | Concrete actions                                                                                                                                                                                                  |
|-----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Severity pressure     | Fix the HIGHs first.  Each HIGH you fix typically lifts severity by 5–10 points.  If most of your weighted total comes from MEDIUMs, batch-triage the ones you've evaluated as not-applicable to your environment. |
| Confidence quality    | Look at the **noisy rules** card on the dashboard.  Rules with high suppression rates pollute the confidence component — either tune the rule or suppress the rule globally so it stops firing.                  |
| Trend                 | Run a scan after each meaningful change.  Even a no-net-change scan lifts the trend off the "first scan" weight=0 floor and into the active 50 baseline.                                                          |
| Triage coverage       | Use the **Triage** page bulk-update flow.  A single 30-minute pass marking obvious false_positives moves this number quickly.  Triaged findings persist via `.nyx/triage.json` so this work isn't wasted on rescans. |
| Regression resistance | Set a baseline (Overview → "Set baseline").  Future scans will then show you specifically which findings re-appeared after being gone.  Investigate those first — they survived a fix once.                       |

## Limitations

The Health Score is honest about what it does *not* measure.  Read
this list before defending or attacking a grade.

* **It is a static-analysis metric.**  Nyx reads source code with
  tree-sitter, taint analysis, and rule packs.  It does not see
  runtime configuration, deployed infrastructure, secrets stored in
  CI variables, IAM policies, container settings, or dependencies'
  vulnerabilities.  A perfect Nyx score does not certify the absence
  of vulnerabilities.
* **It depends on Nyx's rule and language coverage.**  Languages with
  thinner Nyx rule packs (see the
  [language maturity matrix](./language-maturity.md)) will have fewer
  findings flagged, which inflates the score artificially.  A
  Kotlin-heavy repo will look better than its real risk warrants.
* **It scores findings, not damage potential.**  Severity is from the
  rule, not from any model of your specific deployment.  A SQLi sink
  that's only reachable from an internal admin console scores the
  same as one reachable from the public internet.  Reachability data
  is in the finding evidence; the headline score does not consume it.
* **It is repo-local.**  Nothing in the score crosses repo boundaries.
  A monorepo and the same code split into ten repos will produce ten
  different scores.
* **Score 100 ≠ secure.**  100 means "Nyx found nothing under the
  rules it is currently running."  Treat it as a green light to look
  elsewhere for risk, not a final stamp.

## How is this calculated for my repo?

The dashboard tooltip on each component shows the exact numbers Nyx
used: the weighted total, the size factor, which caps applied, and
which components were dropped as not-applicable.  If a component
shows "Not applicable: …", that explains exactly why it didn't
contribute.

Two failure modes you might see and what they mean:

* "Severity pressure: capped at 84 (1 HIGH present)" — the log curve
  produced a higher number, but the 1-2-HIGH cap from §1.4 binds.
  This is intentional; see [the audit](./health-score-audit.md#f4-false-a-grade-for-one-high)
  for why.
* "Triage coverage: Not applicable: only 5 findings (need ≥20 to
  evaluate)" — your repo has too few findings for triage coverage to
  be a meaningful metric, so it's dropped instead of held against
  you.

If your grade still feels wrong after reading the breakdown, the audit
in [`health-score-audit.md`](./health-score-audit.md) lists every
known failure mode of v2 (some still unresolved).  You may be
hitting one of those — and if so, file an issue with the calibration
data so we can revisit a tunable.
