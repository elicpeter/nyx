#!/usr/bin/env python3
"""Render a shell command's output as a PNG sized to its content.

Pipeline:
  1. Run the command, captured through `bash -c` so redirections and
     env vars work, and force colors via `CLICOLOR_FORCE=1`. The whole
     compound is wrapped in a brace group so `2>/dev/null` swallows
     stderr even when the caller chains commands with `;`.
  2. Pipe through `sgr-merge.py` to consolidate consecutive SGR
     sequences (freeze otherwise honors only the last one).
  3. Hand the colored stream to `freeze --execute` at width 1600 with
     window chrome and let height auto-fit the content.

Output is freeze's natural-height capture — short commands stay short,
long commands stay long. The framer (`frame-screenshots.py --natural`)
wraps the result in the brand gradient at the matching outer size, so
no resampling or padding ever happens.

Usage:
    python3 render-cli.py <out.png> <shell command...>
"""
from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

OUT_W = 1600
SCRIPT_DIR = Path(__file__).resolve().parent
SGR_MERGE = SCRIPT_DIR / "sgr-merge.py"


def run_freeze(shell_cmd: str, out_png: Path) -> None:
    """Render the command at width 1600 and font size 22 with window
    chrome. The brace group around the user command makes
    `2>/dev/null` apply to the whole compound — without it, a
    `cmd; true` chain would only redirect `true`'s stderr and leak
    progress bars from `cmd` into the capture."""
    inner = (
        f"{{ CLICOLOR_FORCE=1 {shell_cmd}; }} 2>/dev/null"
        f" | python3 {shlex.quote(str(SGR_MERGE))}"
    )
    subprocess.run(
        [
            "freeze",
            "--execute", f"bash -c {shlex.quote(inner)}",
            "--output", str(out_png),
            "--window",
            "--width", str(OUT_W),
            "--font.size", "22",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: render-cli.py <out.png> <shell command...>", file=sys.stderr)
        return 2
    out = Path(argv[0])
    shell_cmd = " ".join(argv[1:])
    run_freeze(shell_cmd, out)
    print(f"rendered: {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
