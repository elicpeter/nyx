"""
Vulnerable counterpart to safe_fastapi_route_dependencies_auth.py: same
shape but with NO `dependencies=[Depends(...)]` keyword arg on the route
decorator.  The FastAPI ownership-check rule must still fire — the
recognizer must not blanket-suppress every FastAPI route, only those
with an actual dependency-injected auth check.
"""
from fastapi import FastAPI

router = FastAPI()


@router.delete("/{connection_id}")
def delete_connection(connection_id: str, session):
    """No auth — must still fire missing_ownership_check."""
    connection = session.scalar(select(Connection).filter_by(conn_id=connection_id))
    if connection is None:
        raise HTTPException(404, "not found")
    session.delete(connection)
