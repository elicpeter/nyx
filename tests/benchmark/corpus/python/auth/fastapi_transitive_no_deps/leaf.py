"""Leaf router — genuinely unauthenticated (no ancestor declares deps)."""
from typing import Annotated

from fastapi import APIRouter, Body

router = APIRouter()


@router.patch("/{item_id}/state")
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
