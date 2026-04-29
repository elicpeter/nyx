"""py-auth-realrepo-002: pytest `conftest.py` collection hook.

`pytest_collection_modifyitems(config, items)` is invoked by pytest
itself; it never sees user input.  The marker mutation
`item.add_marker(skip_slow)` plus the surrounding boolean-OR
expression text is enough to satisfy the legacy token-override
heuristic by accident, but the function has zero user reach.
"""

import pytest


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-slow"):
        return

    skip_slow = pytest.mark.skip(reason="test is marked as slow")

    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)
