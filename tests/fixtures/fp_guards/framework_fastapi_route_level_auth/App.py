"""
FP guard for FastAPI / Flask route-level dependency-injection auth.

The `dependencies=[Depends(requires_access_dag(...))]` decorator
authorises the entire handler — every value the handler receives,
every row it fetches, and every operation downstream.  The
`is_route_level` flag on the injected AuthCheck tells
`auth_check_covers_subject` to short-circuit `true`, suppressing
`py.auth.missing_ownership_check` on the body's ORM calls (`filter_by`,
`scalar`, …) and on row-variable receivers (`dag.cleanup_runs(...)`).

A bare route with no `dependencies=` keyword is a real ownership-
check FP — the engine must still flag it.  The vulnerable
counterpart lives in
`tests/benchmark/corpus/python/auth/vuln_fastapi_route_no_dependencies.py`.
"""
from fastapi import Depends, FastAPI

router = FastAPI()


def requires_access_dag(method: str, access_entity=None):
    def check():
        ...
    return check


@router.get(
    "/{dag_id}/runs/{run_id}",
    dependencies=[Depends(requires_access_dag(method="GET"))],
)
def get_dag_run(dag_id: str, run_id: str, session):
    """Path params + ORM call covered by route-level guard."""
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
    """Row fetch + row-variable method call covered by route-level guard."""
    dag = session.scalar(select(DagModel).where(DagModel.dag_id == dag_id))
    if dag is None:
        raise HTTPException(404, "not found")
    dag.cleanup_runs(session=session)
