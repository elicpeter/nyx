# Transitive + bare-identifier `include_router` chain.
#
# Exercises TWO previously-unresolved shapes of the cross-file router-dep
# lift (both deferred in `deep_engine_fixes.md`):
#
#   1. Bare-identifier same-file edge — `app_router.include_router(secured)`
#      where `secured` is a sibling router var (no `<module>.<var>` segment).
#      Pre-fix this edge was dropped entirely, so `secured` never inherited
#      `app_router`'s Security dep.
#
#   2. Transitive cross-file chain — the Security dep declared on
#      `app_router` must reach `items.router` through TWO hops
#      (`app_router` -> `secured` -> `v1.router` -> `items.router`), even
#      though every intermediate router declares no deps of its own.
#      Pre-fix resolution was single-hop, so `items.router` inherited
#      nothing and its id-keyed write fired `missing_ownership_check`.
from fastapi import APIRouter, Security

from . import v1, public
from .security import require_auth

# Root of the authenticated chain — carries the scoped Security dep.
app_router = APIRouter(dependencies=[Security(require_auth)])

# (1) Bare-identifier same-file include: `secured` inherits app_router's
# Security dep via the local include_router edge.
secured = APIRouter()
app_router.include_router(secured)

# (2) Cross-file: v1.router attached under `secured`; the dep must flow
# app_router -> secured -> v1.router transitively.
secured.include_router(v1.router, prefix="/v1", tags=["v1"])

# Unsecured chain — recall guard.  `open_router` declares NO deps, so
# everything under it (public.router) is genuinely unauthenticated.
open_router = APIRouter()
open_router.include_router(public.router, prefix="/public", tags=["public"])
