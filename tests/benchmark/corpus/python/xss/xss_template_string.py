from flask import request
from jinja2 import Template

def render_page():
    tmpl = request.args.get('template')
    return Template(tmpl).render()
