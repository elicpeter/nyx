"""Intermediate router — bare, no inline deps.

`router` here is the middle link of the transitive chain
`app_router -> secured -> v1.router -> items.router`.  It declares no
`dependencies=[...]` of its own; the auth comes entirely from the
ancestor routers in `api.py`.  Its only job is to attach `items.router`
one hop further down.
"""
from fastapi import APIRouter

from . import items

router = APIRouter()
router.include_router(items.router, prefix="/items", tags=["items"])
