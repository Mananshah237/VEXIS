"""
LLM Pass 3 — Chain Discovery.

Looks at multiple individually low-to-medium severity findings from the same scan
and identifies attack chains — combinations where path A enables path B to become
a higher-severity attack.

Input: list of CorrelatedFinding (from fuser) with severity in {low, medium, info}
Output: list of ChainFinding dataclasses

The orchestrator creates Finding ORM objects from these and adds them to the DB.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import itertools
import structlog

from app.reasoning.llm_client import LLMClient
from app.reasoning.budget import LLMBudget
from app.correlation.fuser import CorrelatedFinding

log = structlog.get_logger()

# Only consider findings at or below this severity
CHAIN_CANDIDATE_SEVERITIES = {"info", "low", "medium"}
# Maximum group size to send to LLM at once
MAX_GROUP_SIZE = 4
# Minimum confidence for a chain finding to be accepted
CHAIN_CONFIDENCE_THRESHOLD = 0.5
# Maximum number of groups to send to LLM — keep this low to control cost.
# Cross-class groups (different vuln_classes) are prioritized; same-class pairs
# (e.g. log_injection + log_injection) are only included if budget remains.
MAX_CHAIN_GROUPS = 3

SYSTEM_PROMPT = """You are an expert penetration tester who specializes in finding complex, chained attack paths.

You analyze multiple individually low-severity vulnerabilities and determine if they can be combined into a higher-severity attack chain.

Your goal: find cases where exploiting finding A creates the conditions to exploit finding B, resulting in a combined impact greater than either finding alone.

Common chain patterns to look for:
1. Info leak → auth bypass: A path leaks user/session data that can be used to bypass authentication in another path
2. Low-severity write → privilege escalation: Writing to a "safe" location that another path reads with elevated trust
3. Race condition chains: Two concurrent paths that together cause a security violation
4. Session pollution: One path taints shared state that another path later uses dangerously
5. Indirect SQLi: Path A stores attacker data in DB; Path B reads and uses it in a query

Respond ONLY with valid JSON. Be conservative — only report chains you are highly confident about."""

SCHEMA = {
    "type": "object",
    "properties": {
        "chain_found": {"type": "boolean"},
        "chain_description": {"type": "string", "description": "One-sentence description of the chain"},
        "combined_severity": {"type": "string", "enum": ["critical", "high", "medium"]},
        "confidence": {"type": "number", "description": "0.0-1.0"},
        "attack_steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "order": {"type": "integer"},
                    "action": {"type": "string"},
                    "target": {"type": "string"},
                    "finding_index": {"type": "integer", "description": "0-based index into the findings array"},
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
        "reasoning": {"type": "string", "description": "Chain-of-thought explanation of how the chain works"},
        "why_no_chain": {"type": "string", "description": "If chain_found is false, explain why not"},
    },
    "required": ["chain_found", "confidence", "reasoning"],
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
        chain candidates, groups them, and queries LLM for chains.
        """
        candidates = [
            f for f in correlated_findings
            if f.severity in CHAIN_CANDIDATE_SEVERITIES and not f.is_false_positive
        ]
        if len(candidates) < 2:
            log.debug("pass3.skip", reason="fewer than 2 candidates", count=len(candidates))
            return []

        log.info("pass3.start", candidate_count=len(candidates))

        groups = self._group_findings(candidates)
        log.debug("pass3.groups", count=len(groups))

        results: list[ChainFinding] = []
        for group in groups:
            if self._budget and not self._budget.try_consume():
                log.warning("pass3.budget_exhausted")
                break
            chain = await self._analyze_group(group)
            if chain:
                results.append(chain)
                log.info(
                    "pass3.chain_found",
                    title=chain.title,
                    severity=chain.combined_severity,
                    confidence=chain.confidence,
                )

        return results

    def _group_findings(self, findings: list[CorrelatedFinding]) -> list[list[CorrelatedFinding]]:
        """
        Group findings that share context:
          - same source file
          - same sink file
          - overlapping variable names in their taint paths
        Returns a list of groups (each group is 2-4 findings).
        """
        groups: list[list[CorrelatedFinding]] = []
        used = set()

        # Index by file
        by_file: dict[str, list[int]] = {}
        for i, f in enumerate(findings):
            path = f.confirmed.evaluated.taint_path
            files = {path.source.node.file, path.sink.node.file}
            for fn in files:
                by_file.setdefault(fn, []).append(i)

        # Build groups from file-collocated findings
        seen_pairs: set[frozenset] = set()
        for file_indices in by_file.values():
            for combo in itertools.combinations(file_indices, 2):
                pair = frozenset(combo)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                group = [findings[i] for i in combo]
                groups.append(group)

        # Also try groups of 3 for files with many findings
        for file_indices in by_file.values():
            if len(file_indices) >= 3:
                for combo in itertools.combinations(file_indices[:MAX_GROUP_SIZE], 3):
                    triple = frozenset(combo)
                    if triple not in seen_pairs:
                        seen_pairs.add(triple)
                        group = [findings[i] for i in combo]
                        groups.append(group)

        # If no file-collocated groups found, try all pairs
        if not groups and len(findings) >= 2:
            for combo in itertools.combinations(range(len(findings)), 2):
                group = [findings[i] for i in combo]
                groups.append(group)

        # ── Prioritize cross-class groups, cap at MAX_CHAIN_GROUPS ─────────────
        # A group where findings have different vuln_classes is far more
        # interesting than same-class pairs (e.g. log_inj + log_inj adds nothing).
        # Score = number of distinct vuln_classes in the group (higher = better).
        def _cross_class_score(group: list) -> int:
            return len({cf.confirmed.evaluated.taint_path.vuln_class for cf in group})

        cross_class = [g for g in groups if _cross_class_score(g) >= 2]
        same_class  = [g for g in groups if _cross_class_score(g) < 2]

        # Sort cross-class groups: most diverse first
        cross_class.sort(key=_cross_class_score, reverse=True)

        ranked = (cross_class + same_class)[:MAX_CHAIN_GROUPS]
        log.debug("pass3.groups_ranked", total=len(groups), cross_class=len(cross_class), selected=len(ranked))
        return ranked

    async def _analyze_group(self, group: list[CorrelatedFinding]) -> ChainFinding | None:
        """Send a group to the LLM and parse the chain response."""
        finding_blocks = []
        for i, cf in enumerate(group):
            path = cf.confirmed.evaluated.taint_path
            block = (
                f"Finding {i+1} (severity={cf.severity}, vuln_class={path.vuln_class}):\n"
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

        user_prompt = f"""Analyze these {len(group)} individually low/medium severity findings from the same codebase.
Determine if they can be CHAINED into a higher-severity attack.

{chr(10).join(finding_blocks)}

Specifically consider:
1. Can the output/side-effect of Finding 1 be used as input to trigger Finding 2?
2. Do they share state (session, database, cache, filesystem) an attacker could abuse?
3. Can a low-severity info leak (Finding 1) provide the data needed to exploit Finding 2?
4. Can a race condition between paths be exploited?

If chain_found is true, provide:
- chain_description: one sentence describing the chain
- combined_severity: the severity of the COMBINED attack ("critical", "high", or "medium")
- attack_steps: ordered exploit steps referencing finding_index (0-based)
- payload_sequence: the HTTP requests / inputs needed in order
- reasoning: detailed explanation

Be conservative. Only report chains you are highly confident about (confidence > 0.6)."""

        result = await self._client.analyze(SYSTEM_PROMPT, user_prompt, SCHEMA)

        if not result.get("chain_found"):
            return None
        if result.get("confidence", 0) < CHAIN_CONFIDENCE_THRESHOLD:
            return None

        severity = result.get("combined_severity", "medium")
        description = result.get("chain_description", "Multi-step attack chain")

        # Build merged attack flow graph
        merged_nodes, merged_edges = self._merge_attack_flows(group)

        # Compose title
        vuln_classes = list({
            cf.confirmed.evaluated.taint_path.vuln_class for cf in group
        })
        title = f"Attack Chain: {description[:80]}"

        return ChainFinding(
            title=title,
            chain_description=description,
            combined_severity=severity,
            confidence=round(result.get("confidence", 0.7), 2),
            component_findings=group,
            attack_steps=result.get("attack_steps", []),
            payload_sequence=result.get("payload_sequence", []),
            reasoning=result.get("reasoning", ""),
            merged_nodes=merged_nodes,
            merged_edges=merged_edges,
        )

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
        node_offset = 0
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

            # Add chain-link edge between this finding's sink and next finding's source
            sink_id = f"{prefix}node_{len(path.path) - 1}"
            if prev_sink_id is not None:
                source_id = f"{prefix}node_0"
                all_edges.append({
                    "source_id": prev_sink_id,
                    "target_id": source_id,
                    "label": "enables \u2192",
                    "taint_state": "chain",
                    "edge_type": "chain",  # frontend uses this for dashed purple styling
                })
            prev_sink_id = sink_id

        return all_nodes, all_edges
