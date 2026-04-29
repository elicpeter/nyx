"""
Distilled from airflow `airflow-core/src/airflow/api_fastapi/core_api/routes/public/dag_run.py`:

    @dag_run_router.post(
        "",
        dependencies=[Depends(requires_access_dag(method="POST", access_entity=DagAccessEntity.RUN))],
    )
    def trigger_dag_run(dag_id, body, dag_bag, user, session, request):
        dm = session.scalar(select(DagModel).where(DagModel.dag_id == dag_id))
        ...
        dag = get_latest_version_of_dag(dag_bag, dag_id, session)
        dag_run = dag.create_dagrun(run_id=params["run_id"], ...)

The route-level `dependencies=[Depends(requires_access_dag(method="POST",
access_entity=...))]` decorator authorizes the entire handler — the
handler body's `dag.create_dagrun(...)` call (where `dag` is a row
fetched using the auth-checked `dag_id`) must be covered too, even
though the call's subject is the bare row variable rather than the
original id.

Before the route-level fix, `auth_check_covers_subject` walked
`check.subjects` (empty for decorator-level checks whose inner call
carries no per-arg ValueRef) and never matched.  After the fix,
`is_route_level=true` short-circuits coverage to true for any
non-login-guard route-level check, suppressing both the row-fetch
ownership flag and the downstream method-call ownership flag.
"""

from fastapi import Depends, FastAPI

router = FastAPI()


def requires_access_dag(method: str, access_entity=None):
    def check():
        ...
    return check


def get_latest_version_of_dag(dag_bag, dag_id, session):
    return dag_bag.get(dag_id)


@router.get(
    "/{dag_id}/runs/{run_id}",
    dependencies=[Depends(requires_access_dag(method="GET"))],
)
def get_dag_run(dag_id: str, run_id: str, session):
    """
    Route-level guard authorizes the entire handler.  The
    `filter_by(dag_id=dag_id, run_id=run_id)` ORM call must NOT trip
    `py.auth.missing_ownership_check` even though the per-arg subjects
    are id-shaped — the route-level decorator covers them.
    """
    dag_run = session.scalar(
        select(DagRun).filter_by(dag_id=dag_id, run_id=run_id)
    )
    if dag_run is None:
        raise HTTPException(404, "not found")
    return dag_run


@router.delete(
    "/{dag_id}",
    dependencies=[Depends(requires_access_dag(method="DELETE"))],
)
def delete_dag(dag_id: str, session):
    """
    Same shape, DELETE method.  The row fetch and row-variable
    method call must also be fully covered by the route-level guard.
    `dag` is fetched using the auth-checked `dag_id`; without the
    `is_route_level` short-circuit, the per-name walk would mismatch
    `dag.<method>` (subject is the row var) against the check's
    empty subjects vec.
    """
    dag = session.scalar(select(DagModel).where(DagModel.dag_id == dag_id))
    if dag is None:
        raise HTTPException(404, "not found")
    dag.cleanup_runs(session=session)
