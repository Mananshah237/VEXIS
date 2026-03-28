"""
LLM Pass 1 — Sanitizer Evaluation.
For taint paths with sanitizers, evaluate if sanitizers can be bypassed.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import structlog

from app.taint.engine import TaintPath
from app.reasoning.llm_client import LLMClient
from app.reasoning.budget import LLMBudget

log = structlog.get_logger()

SYSTEM_PROMPT = """You are an elite security researcher specializing in source code vulnerability analysis.
You think step-by-step, consider edge cases, and provide concrete proof-of-concept inputs.
You are skeptical — you only confirm a vulnerability when you can demonstrate a working exploit path.
False positives damage your credibility, so you err on the side of "not exploitable" when uncertain."""

SCHEMA = {
    "type": "object",
    "properties": {
        "sanitizer_effective": {"type": "boolean", "description": "True if sanitizer completely prevents exploitation"},
        "bypass_possible": {"type": "boolean", "description": "True if attacker can bypass the sanitizer"},
        "bypass_technique": {"type": "string", "description": "Specific bypass method if possible"},
        "confidence": {"type": "number", "description": "0.0-1.0 confidence that bypass works"},
        "reasoning": {"type": "string", "description": "Step-by-step analysis"},
    },
    "required": ["sanitizer_effective", "bypass_possible", "confidence", "reasoning"],
}


@dataclass
class EvaluatedPath:
    taint_path: TaintPath
    sanitizer_effective: bool = False
    bypass_possible: bool = True
    bypass_technique: str = ""
    llm_confidence: float = 0.5
    llm_reasoning: str = ""
    skip_llm: bool = False  # True if no sanitizers — skip to pass 2
    llm_budget_exhausted: bool = False  # True if LLM call was skipped due to budget


class SanitizerEvaluationPass:
    def __init__(self, budget: LLMBudget | None = None) -> None:
        self._client = LLMClient()
        self._budget = budget

    async def run(self, paths: list[TaintPath]) -> list[EvaluatedPath]:
        results: list[EvaluatedPath] = []
        for path in paths:
            if not path.sanitizers:
                # No sanitizers — taint flows straight to sink, no bypass needed
                results.append(EvaluatedPath(taint_path=path, bypass_possible=True, llm_confidence=0.95, skip_llm=True))
                continue

            # If ALL sanitizers are already marked partial, we know they're bypassable —
            # skip the LLM and pass straight to exploit feasibility.
            all_partial = all(s.is_partial for s in path.sanitizers)
            if all_partial:
                bypass_note = "; ".join(s.description or s.pattern for s in path.sanitizers)
                results.append(EvaluatedPath(
                    taint_path=path,
                    sanitizer_effective=False,
                    bypass_possible=True,
                    bypass_technique=f"Partial sanitizer (known bypassable): {bypass_note}",
                    llm_confidence=0.75,
                    llm_reasoning=f"Sanitizer(s) flagged as incomplete by taint engine: {bypass_note}",
                    skip_llm=True,
                ))
                continue

            # Budget check — skip LLM if exhausted
            if self._budget and not self._budget.try_consume():
                log.warning("pass1.budget_exhausted", path_source=path.source.node.line)
                results.append(EvaluatedPath(
                    taint_path=path,
                    bypass_possible=True,
                    llm_confidence=path.confidence,
                    skip_llm=True,
                    llm_budget_exhausted=True,
                ))
                continue

            evaluated = await self._evaluate_path(path)
            results.append(evaluated)
        return results

    async def _evaluate_path(self, path: TaintPath) -> EvaluatedPath:
        code_snippets = "\n".join(
            f"  Line {n.node.line}: {n.node.code}" for n in path.path
        )
        sanitizer_details = "\n".join(
            f"  - {s.pattern!r}  [{'PARTIAL — known bypassable' if s.is_partial else 'full sanitizer'}]  {s.description}"
            for s in path.sanitizers
        )
        sink_type = path.vuln_class.upper()

        user_prompt = f"""Evaluate whether the sanitizer(s) below actually prevent {sink_type} exploitation.

SOURCE (attacker-controlled):
  File: {path.source.node.file}  Line {path.source.node.line}
  Code: {path.source.node.code}

SINK ({sink_type} operation):
  File: {path.sink.node.file}  Line {path.sink.node.line}
  Code: {path.sink.node.code}

SANITIZERS APPLIED:
{sanitizer_details}

FULL DATA FLOW:
{code_snippets}

Answer these questions:
1. Does each sanitizer completely neutralize the {sink_type} threat, or can it be bypassed?
2. Provide a SPECIFIC bypass string (e.g., for SQLi: `' OR 1=1--`, for CMDi: `; id`, for path: `../../etc/passwd`).
3. State your confidence (0.0–1.0) that a bypass exists."""

        result = await self._client.analyze(SYSTEM_PROMPT, user_prompt, SCHEMA)

        return EvaluatedPath(
            taint_path=path,
            sanitizer_effective=result.get("sanitizer_effective", True),
            bypass_possible=result.get("bypass_possible", False),
            bypass_technique=result.get("bypass_technique", ""),
            llm_confidence=result.get("confidence", 0.5),
            llm_reasoning=result.get("reasoning", ""),
        )
