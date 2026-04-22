"""Phase CF-6 caller: invokes the dense-alias helper and reads one of
the mutated fields.  The caller's primary guarantee is that the scan
*terminates* under the bounded alias graph, not that a particular
finding fires — overflow promotes the callee to "any arg taints any
other," which is a conservative over-approximation but does not blow
up extraction.
"""

import subprocess

from helper import cross_wire


class Box:
    def __init__(self):
        self.buf = ""


def handler(user_input):
    a = Box()
    b = Box()
    c = Box()
    d = Box()
    e = Box()
    # Seed a's buffer with the tainted input, then mix everything.
    a.buf = user_input
    cross_wire(a, b, c, d, e)
    # Read back through a different alias — overflow says any of a..e
    # could carry the taint.
    subprocess.call(c.buf, shell=True)
