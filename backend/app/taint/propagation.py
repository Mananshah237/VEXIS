"""
Taint propagation rules.
Defines how taint flows through different Python constructs.
"""
from __future__ import annotations
from app.taint.engine import TaintType


PROPAGATING_OPERATIONS = [
    "assignment",
    "augmented_assignment",
    "f_string",
    "concatenation",
    "return_statement",
    "function_call_arg",
]

TAINT_CLEARING_OPERATIONS = [
    "int(",
    "float(",
    "bool(",
]


def should_propagate(operation: str) -> bool:
    return operation in PROPAGATING_OPERATIONS


def taint_after_cast(cast_func: str) -> TaintType:
    """Type casts clear taint but may raise exceptions."""
    if cast_func in ("int(", "float(", "bool("):
        return TaintType.CLEARED
    return TaintType.TAINTED
