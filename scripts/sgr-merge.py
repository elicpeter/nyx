#!/usr/bin/env python3
"""Merge consecutive ANSI SGR escape sequences into a single compound form.

freeze (charm.sh) renders only the most recently seen SGR escape, so
the `console` crate's habit of emitting separate `\x1b[34m\x1b[2m\x1b[4m`
sequences erases all but the last attribute. Pipe nyx output through
this filter to consolidate runs into `\x1b[34;2;4m` so freeze keeps
foreground, dim, and underline.

Usage: stream stdin -> stdout, e.g. `nyx scan | python3 sgr-merge.py`.
"""
from __future__ import annotations

import re
import sys

SGR_RUN = re.compile(r"(?:\x1b\[(\d+(?:;\d+)*)m){2,}")


def _merge(match: re.Match) -> str:
    runs = re.findall(r"\x1b\[(\d+(?:;\d+)*)m", match.group(0))
    return "\x1b[" + ";".join(runs) + "m"


def merge_sgr(s: str) -> str:
    return SGR_RUN.sub(_merge, s)


def main() -> int:
    data = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    sys.stdout.buffer.write(merge_sgr(data).encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
