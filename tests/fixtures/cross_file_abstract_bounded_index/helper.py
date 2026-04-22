"""Cross-file callee that returns a fixed integer — the summary's
`return_abstract` baseline already captures `exact(42)` (a Phase 17
intrinsic fact) and CF-3 attaches it as a per-parameter `Clamped`
transfer so the caller synthesises the same bound through the summary
path.  This is the baseline-invariant variant of CF-3 (Clamped), as
distinct from the Identity variant covered by the sibling fixtures.
"""


def safe_index():
    return 42
