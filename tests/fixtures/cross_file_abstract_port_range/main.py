"""A literal-bounded integer is forwarded through a cross-file identity
helper and then used as the payload of a shell command.

Nyx's abstract-domain sink suppression fires on SHELL_ESCAPE when every
tainted leaf is proven integer-typed and bounded.  Without Phase CF-3
the identity helper `passthrough` returns Top (its summary was baseline-
seeded with Top), so the caller loses the `exact(8080)` fact it had on
`port` and the SHELL_ESCAPE sink sees an unbounded integer → finding.
With CF-3 the identity transfer forwards the caller's bound across the
cross-file call and the finding is suppressed.
"""

import subprocess
from helper import passthrough


def run():
    port = 8080
    forwarded = passthrough(port)
    subprocess.run(["/usr/bin/nc", "-l", str(forwarded)], shell=False)
