"""Intermediate router — bare, no deps; one hop of the transitive chain."""
from fastapi import APIRouter

from . import leaf

router = APIRouter()
router.include_router(leaf.router, prefix="/leaf")
