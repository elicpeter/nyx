"""
Distilled from airflow `tests/unit/models/test_backfill.py` and
`providers/google/tests/unit/google/cloud/hooks/test_dlp.py`: pytest test
methods that take a SQLAlchemy `session` fixture by name and call
`session.commit()` / `session.add(...)` / `session.scalar(...)`.

Bare `session.<sqlalchemy_verb>` was previously classified as auth Session
context, which triggered `unit_has_user_input_evidence` even though the
test function takes no user input — the `session` fixture is the
SQLAlchemy ORM Session, not the auth/HTTP session.  After the engine
classifier narrowing, only `session.<identity_field>` (`session.user`,
`session.user_id`, ...) is treated as auth context; SQLAlchemy verbs
do not contribute user-input evidence on their own.
"""


def test_reverse_and_depends_on_past_fails(dep_on_past, dag_maker, session):
    with dag_maker() as dag:
        pass
    session.commit()
    b = _create_backfill(
        dag_id=dag.dag_id,
        from_date="2021-01-01",
        to_date="2021-01-05",
    )
    if dep_on_past:
        assert b is None


def test_create_deidentify_template_with_org_id(self, get_conn, mock_project_id):
    get_conn.return_value.create_deidentify_template.return_value = {}
    result = self.hook.create_deidentify_template(organization_id="ORG_ID")
    assert result == {}
