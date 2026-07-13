"""Leaf router — authorized transitively via the 3-hop ancestor chain.

`router` is bare (`APIRouter()`), so a naive in-file scan sees no auth
and flags the id-keyed write below as `missing_ownership_check`.  The
auth actually lives on `api.py`'s `app_router =
APIRouter(dependencies=[Security(require_auth)])` and reaches this file
through `app_router -> secured (bare local include) -> v1.router
(cross-file) -> items.router (cross-file)`.

Post-fix: the transitive cross-file router-fact resolution walks the
whole ancestor chain and folds `require_auth` into this file's per-route
auth attribution.  The route below must NOT fire
`missing_ownership_check` / `token_override_without_validation`.
"""
from typing import Annotated

from fastapi import APIRouter, Body

router = APIRouter()


@router.patch("/{item_id}/state")
def patch_item_state(
    item_id: str,
    body: Annotated[dict, Body()],
):
    """Bare-leaf route — relies on the root router's Security(require_auth).

    Writes a row keyed by the user-supplied `item_id` path param.  This
    is the canonical transitive FP shape: auth in `api.py`, sink here,
    two intermediate deps-less routers in between.
    """
    new_state = body.get("state", "")
    session = _get_session()
    session.add(
        ItemRow(
            item_id=item_id,
            state=new_state,
        )
    )
    session.commit()


def _get_session():
    raise NotImplementedError


class ItemRow:
    def __init__(self, item_id: str, state: str) -> None:
        self.item_id = item_id
        self.state = state
