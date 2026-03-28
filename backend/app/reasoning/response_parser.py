"""
Structured LLM output parsing.
Validates and extracts fields from LLM JSON responses.
"""
from __future__ import annotations
import json
from typing import Any


def parse_json_response(raw: str) -> dict[str, Any]:
    """Extract JSON from LLM response, handling markdown code blocks."""
    text = raw.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()
    return json.loads(text)
