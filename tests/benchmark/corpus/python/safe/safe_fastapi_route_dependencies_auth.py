"""
Distilled from airflow `airflow-core/src/airflow/api_fastapi/core_api/routes/public/connections.py`:
    @connections_router.delete(
        "/{connection_id}",
        dependencies=[Depends(requires_access_connection(method="DELETE"))],
    )
    def delete_connection(connection_id: str, session: SessionDep):
        connection = session.scalar(select(Connection).filter_by(conn_id=connection_id))
        ...
        session.delete(connection)

The route's `dependencies=[Depends(requires_access_*)]` declares the auth gate at
the FastAPI level.  The ownership-check rule must recognise the dependency-
injected check and not flag the row-fetch / mutation as missing ownership.
"""
from fastapi import Depends, FastAPI

router = FastAPI()


def requires_access_connection(method: str):
    def check():
        ...
    return check


@router.delete(
    "/{connection_id}",
    dependencies=[Depends(requires_access_connection(method="DELETE"))],
)
def delete_connection(connection_id: str, session):
    connection = session.scalar(select(Connection).filter_by(conn_id=connection_id))
    if connection is None:
        raise HTTPException(404, "not found")
    session.delete(connection)


@router.get(
    "/{connection_id}",
    dependencies=[Depends(requires_access_connection(method="GET"))],
)
def get_connection(connection_id: str, session):
    return session.scalar(select(Connection).filter_by(conn_id=connection_id))
