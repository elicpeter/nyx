import os

def get_user_input():
    return os.environ.get("USER_DATA")

def transform(val, escape_html):
    """Branch-sensitive helper: one path sanitizes, one passes through.

    Summary sees: param0 -> return Identity (conservative, since else passes through).
    Body execution: traces the branch based on call-site argument value.
    """
    if escape_html:
        return val.replace("<", "&lt;").replace(">", "&gt;")
    return val
