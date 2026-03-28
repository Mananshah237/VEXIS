"""Detect which web framework the scanned code uses."""
from __future__ import annotations
import re

_FRAMEWORK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("flask",   re.compile(r'from flask\b|import flask\b|flask\.Flask\b', re.MULTILINE)),
    ("django",  re.compile(r'from django\b|import django\b|django\.conf\b', re.MULTILINE)),
    ("fastapi", re.compile(r'from fastapi\b|import fastapi\b|FastAPI\(\)', re.MULTILINE)),
    ("express", re.compile(r"require\(['\"]express['\"]\)|from ['\"]express['\"]", re.MULTILINE)),
    ("nextjs",  re.compile(r"from ['\"]next/|import.*from ['\"]next['\"]", re.MULTILINE)),
]


def detect_framework(source_texts: list[str]) -> str | None:
    """Return the first detected framework name, or None."""
    combined = "\n".join(source_texts[:50])  # limit to first 50 files
    for name, pattern in _FRAMEWORK_PATTERNS:
        if pattern.search(combined):
            return name
    return None
