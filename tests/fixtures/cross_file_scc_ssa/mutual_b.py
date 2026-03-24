from mutual_a import sanitize_html, do_work

def transform(data):
    safe = sanitize_html(data)
    do_work(safe)
    return safe
