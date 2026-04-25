# scripts

Local helpers to run repo-wide tasks without hopping between `./` and `./frontend`.

| Script       | What it does                                                            |
| ------------ | ----------------------------------------------------------------------- |
| `fix.sh`     | Apply all auto-fixes (clippy, fmt, eslint, prettier), then run tests.   |
| `check.sh`   | Verify only (no fixes). Mirrors the GitHub Actions CI workflow.         |

Fixers stream their output (so you can see what changed); tests run quietly and
only show output if they fail. Both scripts print a green/red summary at the end
and exit non-zero if any step failed.

## Usage

```bash
./scripts/fix.sh                # fix everything + run tests
./scripts/fix.sh --no-tests     # just apply fixes
./scripts/fix.sh --rust-only    # skip frontend
./scripts/fix.sh --frontend-only

./scripts/check.sh              # verify everything (CI-equivalent)
./scripts/check.sh --rust-only
```

Scripts can be run from any directory; they resolve the repo root from their
own location.
