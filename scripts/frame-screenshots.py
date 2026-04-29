#!/usr/bin/env python3
"""Frame Nyx serve screenshots with the brand purple gradient.

Reads a list of PNG paths from argv (or all PNGs under
assets/screenshots/ if no args) and overwrites each with a framed
1800x1113 version: inner 1600x992 screenshot with rounded corners,
centered on a diagonal purple gradient (top-left #8a5bf5 →
bottom-right #4d1d97).

Usage:
    python3 scripts/frame-screenshots.py path/to/foo.png [path/to/bar.png ...]
    python3 scripts/frame-screenshots.py            # frames the default set

The output dimensions match the existing framed screenshots in docs
(reverse-engineered: inner=(100,60)–(1700,1052), outer=1800x1113).
Framing is idempotent only when the source is the same size — re-
framing an already-framed image will distort, so callers are expected
to keep raw captures separately or re-capture before re-framing.
"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw

# Frame geometry (matches existing docs/serve-*.png files).
OUTER_W, OUTER_H = 1800, 1113
PAD_L, PAD_T = 100, 60
INNER_W, INNER_H = 1600, 992
CORNER_RADIUS = 12

# Diagonal gradient: top-left → bottom-right.
GRAD_TL = (138, 91, 245)   # #8a5bf5
GRAD_BR = (77, 29, 151)    # #4d1d97


def make_gradient(w: int, h: int) -> Image.Image:
    """Diagonal linear gradient from GRAD_TL (top-left) to GRAD_BR (bottom-right)."""
    img = Image.new("RGB", (w, h))
    pixels = img.load()
    # Project each pixel onto the diagonal axis (0 at TL, 1 at BR).
    denom = (w - 1) + (h - 1)
    for y in range(h):
        for x in range(w):
            t = (x + y) / denom
            r = int(GRAD_TL[0] + (GRAD_BR[0] - GRAD_TL[0]) * t)
            g = int(GRAD_TL[1] + (GRAD_BR[1] - GRAD_TL[1]) * t)
            b = int(GRAD_TL[2] + (GRAD_BR[2] - GRAD_TL[2]) * t)
            pixels[x, y] = (r, g, b)
    return img


def round_corners(img: Image.Image, radius: int) -> Image.Image:
    """Apply rounded corners to img by masking alpha."""
    mask = Image.new("L", img.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, img.size[0], img.size[1]), radius=radius, fill=255
    )
    out = img.convert("RGBA")
    out.putalpha(mask)
    return out


def frame_one(src: Path) -> None:
    inner = Image.open(src).convert("RGB")
    # Resize to the target inner area regardless of input dimensions.
    if inner.size != (INNER_W, INNER_H):
        inner = inner.resize((INNER_W, INNER_H), Image.LANCZOS)
    inner_rounded = round_corners(inner, CORNER_RADIUS)

    canvas = make_gradient(OUTER_W, OUTER_H).convert("RGBA")
    canvas.paste(inner_rounded, (PAD_L, PAD_T), inner_rounded)
    canvas.convert("RGB").save(src, "PNG", optimize=True)
    print(f"framed: {src}", file=sys.stderr)


def main(argv: list[str]) -> int:
    if not argv:
        # No args: walk the default location.
        root = Path(__file__).resolve().parent.parent / "assets" / "screenshots"
        paths = sorted(p for p in root.rglob("*.png"))
    else:
        paths = [Path(p) for p in argv]
    if not paths:
        print("no PNGs to frame", file=sys.stderr)
        return 1
    for p in paths:
        if not p.is_file():
            print(f"skip (not a file): {p}", file=sys.stderr)
            continue
        frame_one(p)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
