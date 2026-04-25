import functools

# `@app.route` and `@functools.lru_cache` are NOT auth decorators.
# The finding should still fire.
@app.route("/run")
@functools.lru_cache(maxsize=32)
def handle_request(request):
    import os
    os.system("ls /tmp")
