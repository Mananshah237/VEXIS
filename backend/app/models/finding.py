from __future__ import annotations
from datetime import datetime
import uuid
from sqlalchemy import String, Float, DateTime, Text, JSON, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    vuln_class: Mapped[str] = mapped_column(String(50), nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    source_file: Mapped[str] = mapped_column(Text, nullable=False)
    source_line: Mapped[int] = mapped_column(Integer, nullable=False)
    source_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    sink_file: Mapped[str] = mapped_column(Text, nullable=False)
    sink_line: Mapped[int] = mapped_column(Integer, nullable=False)
    sink_code: Mapped[str | None] = mapped_column(Text, nullable=True)

    taint_path: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    attack_flow: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    poc: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    llm_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    taint_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    remediation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    chain_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # set for vuln_class="chain"

    triage_status: Mapped[str] = mapped_column(String(30), default="open")
    triage_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    @classmethod
    def from_correlated(cls, scan_id, finding_data, poc, classification) -> "Finding":
        from app.exploit.attack_flow import build_attack_flow
        from app.reasoning.pass_2_exploit import BUDGET_EXHAUSTED_REASONING
        cf = finding_data.confirmed
        path = cf.evaluated.taint_path

        # Compose description — append dedup note if multiple paths collapsed
        description = classification.description
        if finding_data.dedup_count > 1:
            description += f" ({finding_data.dedup_count - 1} similar finding{'s' if finding_data.dedup_count > 2 else ''} at same sink deduplicated)"

        # LLM reasoning — note budget exhaustion if applicable
        llm_reasoning = cf.reasoning
        if cf.llm_budget_exhausted:
            llm_reasoning = BUDGET_EXHAUSTED_REASONING

        return cls(
            id=uuid.uuid4(),
            scan_id=scan_id,
            title=classification.title,
            severity=finding_data.severity,
            confidence=finding_data.combined_confidence,
            vuln_class=path.vuln_class,
            cwe_id=classification.cwe_id,
            owasp_category=classification.owasp_category,
            mitre_technique=classification.mitre_technique,
            description=description,
            source_file=path.source.node.file,
            source_line=path.source.node.line,
            source_code=path.source.node.code,
            sink_file=path.sink.node.file,
            sink_line=path.sink.node.line,
            sink_code=path.sink.node.code,
            taint_path={"path": [{"file": n.node.file, "line": n.node.line, "code": n.node.code, "taint_type": n.taint_type} for n in path.path]},
            attack_flow=build_attack_flow(path),
            poc={"attack_vector": poc.attack_vector, "payload": poc.payload, "preconditions": poc.preconditions, "steps": [{"order": s.order, "action": s.action, "target": s.target, "input": s.input_data, "explanation": s.explanation} for s in poc.steps], "expected_outcome": poc.expected_outcome},
            llm_reasoning=llm_reasoning,
            llm_confidence=cf.llm_confidence,
            taint_confidence=path.confidence,
        )

    @classmethod
    def from_chain(cls, scan_id, chain_finding) -> "Finding":
        """Create a Finding from a ChainFinding (Pass 3 output)."""
        from app.exploit.classifier import VULN_CLASS_TO_CWE, VULN_CLASS_TO_OWASP
        import uuid

        # Use first and last component for source/sink display
        first = chain_finding.component_findings[0].confirmed.evaluated.taint_path
        last = chain_finding.component_findings[-1].confirmed.evaluated.taint_path

        component_summary = [
            {
                "vuln_class": cf.confirmed.evaluated.taint_path.vuln_class,
                "severity": cf.severity,
                "source": f"{cf.confirmed.evaluated.taint_path.source.node.file}:{cf.confirmed.evaluated.taint_path.source.node.line}",
                "sink": f"{cf.confirmed.evaluated.taint_path.sink.node.file}:{cf.confirmed.evaluated.taint_path.sink.node.line}",
            }
            for cf in chain_finding.component_findings
        ]

        return cls(
            id=uuid.uuid4(),
            scan_id=scan_id,
            title=chain_finding.title,
            severity=chain_finding.combined_severity,
            confidence=chain_finding.confidence,
            vuln_class="chain",
            cwe_id=None,
            owasp_category="A04:2021 - Insecure Design",
            mitre_technique="T1190 - Exploit Public-Facing Application",
            description=chain_finding.chain_description,
            source_file=first.source.node.file,
            source_line=first.source.node.line,
            source_code=first.source.node.code,
            sink_file=last.sink.node.file,
            sink_line=last.sink.node.line,
            sink_code=last.sink.node.code,
            taint_path={
                "type": "chain",
                "chain_description": chain_finding.chain_description,
                "path": chain_finding.merged_nodes,
            },
            attack_flow={
                "nodes": chain_finding.merged_nodes,
                "edges": chain_finding.merged_edges,
            },
            poc={
                "chain_description": chain_finding.chain_description,
                "payload_sequence": chain_finding.payload_sequence,
                "attack_steps": chain_finding.attack_steps,
                "component_findings": component_summary,
            },
            llm_reasoning=chain_finding.reasoning,
            llm_confidence=chain_finding.confidence,
            taint_confidence=None,
            chain_data={
                "component_count": len(chain_finding.component_findings),
                "component_summary": component_summary,
                "attack_steps": chain_finding.attack_steps,
                "payload_sequence": chain_finding.payload_sequence,
            },
        )
