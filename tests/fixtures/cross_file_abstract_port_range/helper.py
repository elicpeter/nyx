"""Identity-passthrough helper in a separate file.

Without a per-parameter abstract transfer channel the SSA summary for
`passthrough` records `return_abstract = Top` because the pass-1
baseline probe seeded the parameter with Top — the structural fact
that the return IS the parameter is lost to the summary.  With the
per-parameter channel the summary also carries
`abstract_transfer[0] = Identity`, so a caller can forward interval
bounds it already knows about the argument through the call.
"""


def passthrough(value):
    return value
