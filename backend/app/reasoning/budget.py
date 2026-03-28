"""LLM call budget tracker — shared across analysis passes in a single scan."""
from __future__ import annotations


class LLMBudget:
    """Tracks LLM calls remaining for a single scan. Thread-safe for single-threaded async use."""

    def __init__(self, max_calls: int) -> None:
        self.max_calls = max_calls
        self._calls = 0

    def try_consume(self) -> bool:
        """Consume one LLM call slot. Returns True if allowed, False if budget exhausted."""
        if self._calls >= self.max_calls:
            return False
        self._calls += 1
        return True

    @property
    def exhausted(self) -> bool:
        return self._calls >= self.max_calls

    @property
    def calls_made(self) -> int:
        return self._calls

    @property
    def calls_remaining(self) -> int:
        return max(0, self.max_calls - self._calls)
