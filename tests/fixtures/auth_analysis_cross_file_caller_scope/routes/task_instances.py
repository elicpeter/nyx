"""Authorized route handler (cross-file caller-scope IPA — safe side).

Distilled from airflow
`airflow-core/src/airflow/api_fastapi/execution_api/routes/` + the
sentry/saleor `route in api/, helper in services/` cross-file delegation
shape.

`ti_update_state` is route-level authorized via the same-file
`ti_id_router = APIRouter(dependencies=[Security(require_auth,
scopes=["ti:self"])])` declaration.  It performs no sink of its own — it
delegates the actual `session.add(...)` to the private helper
`persist_ti_state_change` defined in `services/state.py` (a DIFFERENT
file).

Phase 1 caller-scope IPA (`apply_caller_scope_propagation`) is scoped per
file, so it refuses to lift onto a helper with no in-file caller — every
`session.add` in `services/state.py` fired `missing_ownership_check` /
`token_override_without_validation`.  Phase 2 (`caller_scope.rs`) records,
in pass 1, that every caller of `persist_ti_state_change` across the whole
index is an authorized route handler, and lifts the route-level checks
onto the helper at pass 2.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, Security

from services.state import persist_ti_state_change


def require_auth():
    pass


ti_id_router = APIRouter(
    dependencies=[Security(require_auth, scopes=["ti:self"])],
)


@ti_id_router.patch("/{task_instance_id}/state")
def ti_update_state(
    task_instance_id: UUID,
    payload: Annotated[dict, Body()],
    session,
) -> None:
    persist_ti_state_change(
        task_instance_id=task_instance_id,
        payload=payload,
        session=session,
    )
