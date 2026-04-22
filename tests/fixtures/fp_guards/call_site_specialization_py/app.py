"""FP GUARD — cross-call-site specialization (Python: safe caller only).

``run_it`` forwards its argument to ``subprocess.run`` with
``shell=True``.  The only caller in this file passes a constant
string, so the inline k=1 analysis must see the safe cap and not
emit a taint flow.  A separate TP fixture exists for the tainted
caller path; keeping this fixture safe-only makes the FP-guard
assertion unambiguous.

Expected: NO taint-unsanitised-flow finding.
"""
import subprocess


def run_it(cmd):
    subprocess.run(cmd, shell=True, check=False)


def entry():
    run_it("/usr/bin/uptime")   # constant arg only
