"""Public router — attached under `open_router` (NO deps) — recall guard.

`api.py` declares `open_router = APIRouter()` (no `dependencies=[...]`)
and `open_router.include_router(public.router, ...)`.  The ancestor
chain for this router carries NO auth, so the id-keyed write below is
genuinely unauthenticated and `py.auth.missing_ownership_check` MUST
still fire.

If the transitive lift over-applied (e.g. lifting deps from any router
regardless of whether an ancestor actually declares them), this real
finding would silently disappear — the vulnerable counterpart proving
the fix does not over-suppress.
"""
from typing import Annotated

from fastapi import APIRouter, Body

router = APIRouter()


@router.put("/{log_id}/payload")
def public_update_log(
    log_id: str,
    body: Annotated[dict, Body()],
):
    """Public route — no auth covers this id-targeted write."""
    session = _get_session()
    session.add(
        LogRow(
            log_id=log_id,
            payload=body.get("payload", ""),
        )
    )
    session.commit()


def _get_session():
    raise NotImplementedError


class LogRow:
    def __init__(self, log_id: str, payload: str) -> None:
        self.log_id = log_id
        self.payload = payload
