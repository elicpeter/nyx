"""FP GUARD — type-driven suppression (int port).

The tainted env string is parsed with int() — a known sanitiser that
covers every capability when the result type is integer (not a string
context).  Binding a socket to (host, int_port) must therefore not
produce a SQL/FILE_IO/SHELL flow finding.

Expected: NO taint-unsanitised-flow finding.
"""
import os
import socket


def start():
    raw = os.environ.get("PORT", "8080")
    port = int(raw)                     # int() covers Cap::all for this flow
    s = socket.socket()
    s.bind(("127.0.0.1", port))
    s.listen(1)
