"""UNauthorized route handler (cross-file caller-scope IPA — recall guard).

`purge_dag_run` is attached to a BARE router (`dr_router = APIRouter()`
with no `dependencies=[Security(...)]`), so it carries no route-level
auth.  It delegates to the private helper `delete_dag_run_row` in
`services/dag_run_ops.py`.

Because the helper's only caller is unauthorized, the Phase 2 cross-file
accumulator records `all_authorized = false`, the lift is refused, and
`missing_ownership_check` MUST still fire on the helper's sink.  Without
this guard an over-broad cross-file lift would silently suppress a real
finding.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body

from services.dag_run_ops import delete_dag_run_row


# Bare router — no Security dep at the boundary.
dr_router = APIRouter()


@dr_router.delete("/{dag_run_id}")
def purge_dag_run(
    dag_run_id: UUID,
    payload: Annotated[dict, Body()],
    session,
) -> None:
    delete_dag_run_row(
        dag_run_id=dag_run_id,
        payload=payload,
        session=session,
    )
