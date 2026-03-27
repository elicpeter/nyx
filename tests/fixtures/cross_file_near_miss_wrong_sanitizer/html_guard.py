import html


def protect_html(s):
    """Returns an HTML-entity-encoded version of `s`.

    This is an HTML_ESCAPE sanitiser — it neutralises XSS by replacing
    characters like < > & " '.  It does NOT provide SQL injection protection
    (it does not escape single quotes in a way that is safe for SQL contexts).

    A caller that applies this before a SQL sink and assumes it is safe is
    making a category error: the sanitiser caps do not match.
    """
    return html.escape(s)
