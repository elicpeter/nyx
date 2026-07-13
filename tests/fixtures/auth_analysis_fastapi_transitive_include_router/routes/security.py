"""Stub for the auth dependency callable referenced by the root router."""


def require_auth():
    """Validates a bearer JWT, raises HTTPException(401) on failure.

    Declaration-only stub — the auth analysis cares about the
    router-level wrapper placement, not the body.
    """
    return None
