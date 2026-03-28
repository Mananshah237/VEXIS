"""
Confidence score calculation for correlated findings.
"""
from __future__ import annotations


def calculate_combined_confidence(
    taint_confidence: float,
    llm_confidence: float,
    taint_weight: float = 0.4,
    llm_weight: float = 0.6,
) -> float:
    """Weighted combination of taint engine and LLM confidence scores."""
    combined = (taint_confidence * taint_weight) + (llm_confidence * llm_weight)
    return round(min(max(combined, 0.0), 1.0), 2)
