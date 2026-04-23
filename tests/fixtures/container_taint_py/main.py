# Phase 8.3 regression: a tainted value is appended to a list and later
# read back via subscript before being sunk.  This exercises container-
# element taint — a known heap-aliasing limitation called out in the
# pre-release audit.
#
# Phase 11 (cross-function container identity) is expected to close this
# gap.  For now the fixture is codified as a known-gap coverage test.
import os
import subprocess

items = []
items.append(os.environ["INPUT"])
subprocess.run(items[0], shell=True)
