import os
from sanitizer import clean_html

data = os.environ["INPUT"]
safe = clean_html(data)
os.system(safe)
