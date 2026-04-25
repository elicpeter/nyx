# py-safe-015: Optional[str]-returning sanitiser with None failure sentinel.
import os
from typing import Optional
from flask import request


def sanitize_path(s: str) -> Optional[str]:
    if ".." in s or s.startswith("/") or s.startswith("\\"):
        return None
    return s


def main() -> None:
    raw = request.args.get("path")
    safe = sanitize_path(raw)
    if safe is None:
        return
    with open(safe) as f:
        f.read()
