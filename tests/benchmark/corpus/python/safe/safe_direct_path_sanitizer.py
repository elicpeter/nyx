# py-safe-014: direct-return path sanitiser (Optional[str]) closing the
# OR-chain rejection path.  Mirrors rs-safe-014.
import os
from flask import request


def sanitize_path(s: str) -> str:
    if ".." in s or s.startswith("/") or s.startswith("\\"):
        return ""
    return s


def main() -> None:
    raw = request.args.get("path")
    safe = sanitize_path(raw)
    with open(safe) as f:
        f.read()
