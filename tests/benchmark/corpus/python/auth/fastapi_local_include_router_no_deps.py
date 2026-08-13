"""Vuln: bare-identifier `include_router` where the parent has NO deps.

`outer` declares no `dependencies=[...]`, so attaching the bare sibling
`inner` via `outer.include_router(inner)` lifts nothing.  The id-keyed
write below is genuinely unauthenticated and MUST fire
`py.auth.missing_ownership_check`.

Vulnerable counterpart to `fastapi_local_include_router_auth.py` — proves
the bare-identifier local edge does not over-suppress when no ancestor
router actually declares a dependency.
"""
from typing import Annotated

from fastapi import APIRouter, Body


outer = APIRouter()
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
