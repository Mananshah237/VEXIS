"""
LLM Pass 3 — Chain Discovery.

Looks at multiple individually low-to-medium severity findings from the same scan
and identifies attack chains — combinations where path A enables path B to become
a higher-severity attack.

Input: list of CorrelatedFinding (from fuser) with severity in {low, medium, info}
Output: list of ChainFinding dataclasses

Instead of one LLM call per finding-pair, this pass sends ALL candidates in a
single batched prompt (max BATCH_SIZE findings per call) and asks the model to
identify every chain in one shot. This reduces N*(N-1)/2 calls to ceil(N/BATCH_SIZE).

The orchestrator creates Finding ORM objects from these and adds them to the DB.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import asyncio
import math
import structlog

from app.reasoning.llm_client import LLMClient
from app.reasoning.budget import LLMBudget
from app.correlation.fuser import CorrelatedFinding

log = structlog.get_logger()

# Only consider findings at or below this severity
CHAIN_CANDIDATE_SEVERITIES = {"info", "low", "medium"}
# Maximum findings to include in a single LLM batch call
BATCH_SIZE = 6
# Minimum confidence for a chain finding to be accepted
CHAIN_CONFIDENCE_THRESHOLD = 0.5

SYSTEM_PROMPT = """You are an expert penetration tester who specializes in finding complex, chained attack paths.

You analyze multiple individually low-severity vulnerabilities and determine if any can be combined into higher-severity attack chains.

Your goal: find cases where exploiting finding A creates the conditions to exploit finding B, resulting in a combined impact greater than either finding alone.

Common chain patterns to look for:
1. Info leak → auth bypass: A path leaks user/session data that can be used to bypass authentication in another path
2. Low-severity write → privilege escalation: Writing to a "safe" location that another path reads with elevated trust
3. Race condition chains: Two concurrent paths that together cause a security violation
4. Session pollution: One path taints shared state that another path later uses dangerously
5. Indirect SQLi: Path A stores attacker data in DB; Path B reads and uses it in a query

Respond ONLY with valid JSON. Be conservative — only report chains you are highly confident about."""

# Schema for batched response: array of chains found across ALL findings
BATCH_SCHEMA = {
    "type": "object",
    "properties": {
        "chains": {
            "type": "array",
            "description": "All attack chains found. Empty array if none.",
            "items": {
                "type": "object",
                "properties": {
                    "chain_description": {"type": "string", "description": "One-sentence description of the chain"},
                    "combined_severity": {"type": "string", "enum": ["critical", "high", "medium"]},
                    "confidence": {"type": "number", "description": "0.0-1.0"},
                    "component_indices": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "0-based indices into the findings array for findings involved in this chain",
                    },
                    "attack_steps": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "order": {"type": "integer"},
                                "action": {"type": "string"},
                                "target": {"type": "string"},
                                "finding_index": {"type": "integer"},
                            },
                            "required": ["order", "action", "target", "finding_index"],
                        },
                    },
                    "payload_sequence": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "step": {"type": "integer"},
                                "method": {"type": "string"},
                                "path": {"type": "string"},
                                "payload": {"type": "string"},
                                "purpose": {"type": "string"},
                            },
                            "required": ["step", "method", "path", "payload", "purpose"],
                        },
                    },
                    "reasoning": {"type": "string"},
                },
                "required": ["chain_description", "combined_severity", "confidence", "component_indices", "reasoning"],
            },
        },
    },
    "required": ["chains"],
}


@dataclass
class ChainFinding:
    """Represents a chained attack discovered by Pass 3."""
    title: str
    chain_description: str
    combined_severity: str
    confidence: float
    component_findings: list[CorrelatedFinding]
    attack_steps: list[dict]
    payload_sequence: list[dict]
    reasoning: str
    # Merged attack flow graph
    merged_nodes: list[dict] = field(default_factory=list)
    merged_edges: list[dict] = field(default_factory=list)


class ChainDiscoveryPass:
    def __init__(self, budget: LLMBudget | None = None) -> None:
        self._client = LLMClient()
        self._budget = budget

    async def run(self, correlated_findings: list[CorrelatedFinding]) -> list[ChainFinding]:
        """
        Entry point. Takes all correlated findings from the scan, filters to
        chain candidates, and sends them in batches to the LLM.
        """
        candidates = [
            f for f in correlated_findings
            if f.severity in CHAIN_CANDIDATE_SEVERITIES and not f.is_false_positive
        ]
        if len(candidates) < 2:
            log.debug("pass3.skip", reason="fewer than 2 candidates", count=len(candidates))
            return []

        log.info("pass3.start", candidate_count=len(candidates))

        # Split into batches of BATCH_SIZE
        batches = [
            candidates[i:i + BATCH_SIZE]
            for i in range(0, len(candidates), BATCH_SIZE)
        ]

        results: list[ChainFinding] = []
        for batch in batches:
            if self._budget and not self._budget.try_consume():
                log.warning("pass3.budget_exhausted")
                break
            chains = await self._analyze_batch(batch)
            results.extend(chains)
            if chains:
                for c in chains:
                    log.info(
                        "pass3.chain_found",
                        title=c.title,
                        severity=c.combined_severity,
                        confidence=c.confidence,
                    )

        return results

    async def _analyze_batch(self, batch: list[CorrelatedFinding]) -> list[ChainFinding]:
        """Send a batch of findings to the LLM and parse all chains from the response."""
        finding_blocks = []
        for i, cf in enumerate(batch):
            path = cf.confirmed.evaluated.taint_path
            block = (
                f"Finding {i} (severity={cf.severity}, vuln_class={path.vuln_class}):\n"
                f"  Source: {path.source.node.file}:{path.source.node.line}\n"
                f"    Code: {path.source.node.code}\n"
                f"  Sink: {path.sink.node.file}:{path.sink.node.line}\n"
                f"    Code: {path.sink.node.code}\n"
                f"  Taint path ({len(path.path)} steps):\n"
            )
            for j, node in enumerate(path.path):
                block += f"    Step {j+1}: {node.node.file}:{node.node.line}: {node.node.code[:80]}\n"
            if cf.confirmed.reasoning:
                block += f"  LLM note: {cf.confirmed.reasoning[:150]}\n"
            finding_blocks.append(block)

        user_prompt = f"""Analyze these {len(batch)} individually low/medium severity findings from the same codebase.
Identify ALL attack chains where one finding enables or amplifies another.

{chr(10).join(finding_blocks)}

For each chain found:
- chain_description: one sentence
- combined_severity: severity of the COMBINED attack ("critical", "high", or "medium")
- confidence: 0.0-1.0 (only include chains with confidence > 0.6)
- component_indices: 0-based indices of findings involved
- attack_steps: ordered exploit steps
- payload_sequence: HTTP requests / inputs in order
- reasoning: detailed explanation

Return an empty "chains" array if no confident chains exist. Be conservative."""

        result = await self._client.analyze(SYSTEM_PROMPT, user_prompt, BATCH_SCHEMA)

        chains_data = result.get("chains", [])
        if not isinstance(chains_data, list):
            return []

        chain_findings: list[ChainFinding] = []
        for chain_data in chains_data:
            confidence = chain_data.get("confidence", 0)
            if confidence < CHAIN_CONFIDENCE_THRESHOLD:
                continue

            component_indices = chain_data.get("component_indices", [])
            # Validate indices are in range
            valid_indices = [i for i in component_indices if 0 <= i < len(batch)]
            if len(valid_indices) < 2:
                continue

            component_findings = [batch[i] for i in valid_indices]
            description = chain_data.get("chain_description", "Multi-step attack chain")
            severity = chain_data.get("combined_severity", "medium")

            merged_nodes, merged_edges = self._merge_attack_flows(component_findings)

            chain_findings.append(ChainFinding(
                title=f"Attack Chain: {description[:80]}",
                chain_description=description,
                combined_severity=severity,
                confidence=round(confidence, 2),
                component_findings=component_findings,
                attack_steps=chain_data.get("attack_steps", []),
                payload_sequence=chain_data.get("payload_sequence", []),
                reasoning=chain_data.get("reasoning", ""),
                merged_nodes=merged_nodes,
                merged_edges=merged_edges,
            ))

        return chain_findings

    def _merge_attack_flows(
        self, group: list[CorrelatedFinding]
    ) -> tuple[list[dict], list[dict]]:
        """
        Merge the attack flow graphs of all findings in the group into one graph.
        Adds dashed "chain" edges connecting the sink of finding N to the source
        of finding N+1 (when they share file/variable context).
        """
        all_nodes: list[dict] = []
        all_edges: list[dict] = []
        prev_sink_id: str | None = None

        for i, cf in enumerate(group):
            path = cf.confirmed.evaluated.taint_path
            prefix = f"chain{i}_"

            for j, taint_node in enumerate(path.path):
                node_type = "source" if j == 0 else ("sink" if j == len(path.path) - 1 else "transform")
                node_id = f"{prefix}node_{j}"
                all_nodes.append({
                    "id": node_id,
                    "type": node_type,
                    "label": taint_node.node.code[:50],
                    "file": taint_node.node.file,
                    "line": taint_node.node.line,
                    "code": taint_node.node.code,
                    "taint_type": taint_node.taint_type,
                    "is_vulnerable": (node_type == "sink"),
                    "chain_component": i,
                })
                if j > 0:
                    all_edges.append({
                        "source_id": f"{prefix}node_{j-1}",
                        "target_id": node_id,
                        "label": taint_node.label,
                        "taint_state": taint_node.taint_type,
                        "edge_type": "taint",
                    })

            sink_id = f"{prefix}node_{len(path.path) - 1}"
            if prev_sink_id is not None:
                source_id = f"{prefix}node_0"
                all_edges.append({
                    "source_id": prev_sink_id,
                    "target_id": source_id,
                    "label": "enables \u2192",
                    "taint_state": "chain",
                    "edge_type": "chain",
                })
            prev_sink_id = sink_id

        return all_nodes, all_edges
