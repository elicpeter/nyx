import html
from mutual_b import transform

def do_work(data):
    result = transform(data)
    return result

def sanitize_html(data):
    return html.escape(data)
