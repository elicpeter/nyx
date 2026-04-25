"""FP GUARD — type-driven suppression (bool flag).

A tainted env variable is coerced to bool via explicit comparison.
The resulting boolean is used to guard a branch — it never reaches
any sink directly.  The engine should not emit a taint finding.

Expected: NO taint-unsanitised-flow finding.
"""
import os
import subprocess


def maybe_run():
    raw = os.environ.get("DRY_RUN", "")
    dry_run = raw == "1"              # bool — cannot carry a shell payload
    if dry_run:
        print("skipping")
        return
    subprocess.run(["/usr/bin/uptime"], check=False)
