"""Safe root: Security dep flows transitively to a 2-hop-deep leaf.

`app_router` carries `Security(require_auth)`.  It attaches the bare
sibling `secured` (bare-identifier local edge), which attaches
`v1.router` (cross-file), which attaches `leaf.router` (cross-file).
FastAPI lifts `app_router`'s dependency onto every route under the whole
chain, so the id-keyed write in `leaf.py` is authorized and must NOT
fire — even though `secured`, `v1.router`, and `leaf.router` each
declare no deps of their own.
"""
from fastapi import APIRouter, Security

from . import v1
from .security import require_auth

app_router = APIRouter(dependencies=[Security(require_auth)])

secured = APIRouter()
app_router.include_router(secured)

secured.include_router(v1.router, prefix="/v1")
