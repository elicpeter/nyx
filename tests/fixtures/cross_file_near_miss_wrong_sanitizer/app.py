import sqlite3

from flask import request

from html_guard import protect_html


def search():
    """NEAR MISS — TRUE POSITIVE.

    The developer applied an HTML escape (from html_guard.py) to the user
    input before passing it to a SQL query.  This looks superficially safe
    but is NOT: html.escape() is an HTML_ESCAPE sanitiser and does not
    neutralise SQL injection (Cap::SQL_QUERY capability).

    Nyx should still report a taint-unsanitised-flow here because the
    SQL_QUERY capability of the taint was never eliminated.

    This fixture is specifically designed to expose false-negative traps:
    tools that treat any sanitiser call as clearing all taint would miss this.
    """
    term = request.args.get("q")     # taint source (Cap::all)
    escaped = protect_html(term)     # HTML_ESCAPE only — SQL cap still live
    conn = sqlite3.connect("app.db")
    # VULN: SQL injection — protect_html() does not sanitise for SQL
    conn.execute(
        "SELECT * FROM items WHERE name = '" + escaped + "'"
    )
