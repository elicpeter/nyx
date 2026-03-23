import bleach

def clean_html(data):
    return bleach.clean(data)
