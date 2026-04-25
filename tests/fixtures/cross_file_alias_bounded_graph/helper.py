"""Points-to dense-alias fixture: dense alias graph in a single helper.

The helper accepts five parameters and writes each one into a field of
each other, producing ~20 raw alias edges.  The bounded-size invariant
must cap the summary at MAX_ALIAS_EDGES (8) and fall back to the
conservative `overflow = true` behaviour without exploding extraction
time or summary size.
"""


def cross_wire(a, b, c, d, e):
    # Each parameter's `.buf` field is overwritten with every other
    # parameter's value — a 5x4 = 20-edge alias graph that exceeds the
    # MAX_ALIAS_EDGES cap.
    a.buf = b
    a.buf = c
    a.buf = d
    a.buf = e
    b.buf = a
    b.buf = c
    b.buf = d
    b.buf = e
    c.buf = a
    c.buf = b
    c.buf = d
    c.buf = e
    d.buf = a
    d.buf = b
    d.buf = c
    d.buf = e
    e.buf = a
    e.buf = b
    e.buf = c
    e.buf = d
