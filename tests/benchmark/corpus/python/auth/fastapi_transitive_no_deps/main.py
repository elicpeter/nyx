"""Vuln root: transitive chain where NO ancestor declares a dependency.

`outer` has no `dependencies=[...]`.  It attaches the bare sibling `mid`
(bare-identifier local edge), which attaches `leaf.router` (cross-file).
No router in the chain carries auth, so the transitive resolver lifts
nothing and the id-keyed write in `leaf.py` MUST fire.

Vulnerable counterpart to `python/safe/fastapi_transitive_include_router/`
— proves transitive resolution does not hallucinate deps down a
deps-less chain.
"""
from fastapi import APIRouter

from . import leaf

outer = APIRouter()

mid = APIRouter()
outer.include_router(mid)

mid.include_router(leaf.router, prefix="/leaf")
