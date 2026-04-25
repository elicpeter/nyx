"""Cross-file callee that returns a fixed integer — the summary's
`return_abstract` baseline already captures `exact(42)` (an abstract-
interpretation intrinsic fact) and the abstract transfer channel
attaches it as a per-parameter `Clamped` transfer so the caller
synthesises the same bound through the summary path.  This is the
baseline-invariant variant (Clamped), as distinct from the Identity
variant covered by the sibling fixtures.
"""


def safe_index():
    return 42
