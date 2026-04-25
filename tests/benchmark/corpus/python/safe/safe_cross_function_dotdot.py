# py-safe-016: cross-function bool-returning validator with rejection.
from flask import request


def validate_no_dotdot(s: str) -> bool:
    return ".." not in s and not s.startswith("/") and not s.startswith("\\")


def main() -> None:
    raw = request.args.get("path")
    if not validate_no_dotdot(raw):
        return
    with open(raw) as f:
        f.read()
