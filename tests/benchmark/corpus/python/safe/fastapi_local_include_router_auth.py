"""Safe: bare-identifier same-file `include_router` lifts auth onto child.

`outer` carries a scoped `Security(require_auth)` dependency and attaches
the bare sibling router `inner` via `outer.include_router(inner)` — a
bare-identifier (no `<module>.<var>`) edge.  FastAPI propagates `outer`'s
dependency onto every route under `inner`, so the id-keyed write below is
authorized and must NOT fire `py.auth.missing_ownership_check`.

Regression guard for the same-file bare-identifier gap in the cross-file
router-fact resolver (deep_engine_fixes.md, 2026-05-04).
"""
from typing import Annotated

from fastapi import APIRouter, Body, Security


def require_auth():
    return None


outer = APIRouter(dependencies=[Security(require_auth)])
inner = APIRouter()
outer.include_router(inner)


@inner.patch("/{item_id}/state")
def patch_item(item_id: str, body: Annotated[dict, Body()]):
    session = _get_session()
    session.add(ItemRow(item_id=item_id, state=body.get("state", "")))
    session.commit()


def _get_session():
    raise NotImplementedError


class ItemRow:
    def __init__(self, item_id: str, state: str) -> None:
        self.item_id = item_id
        self.state = state
