"""
Correlation & Fusion — merges taint engine results with LLM analysis.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import structlog

from app.reasoning.pass_2_exploit import ConfirmedFinding

log = structlog.get_logger()


@dataclass
class CorrelatedFinding:
    confirmed: ConfirmedFinding
    taint_confidence: float
    llm_confidence: float
    combined_confidence: float
    is_true_positive: bool
    needs_manual_review: bool
    is_false_positive: bool
    severity: str
    dedup_count: int = 1  # >1 means N similar findings at the same sink were collapsed


class CorrelationFuser:
    def fuse(self, confirmed_findings: list[ConfirmedFinding]) -> list[CorrelatedFinding]:
        results: list[CorrelatedFinding] = []
        for cf in confirmed_findings:
            taint_conf = cf.evaluated.taint_path.confidence
            llm_conf = cf.llm_confidence

            combined = (taint_conf * 0.4) + (llm_conf * 0.6)

            is_tp = taint_conf >= 0.6 and llm_conf >= 0.6 and cf.exploitable
            is_fp = taint_conf < 0.4 or (llm_conf < 0.3 and not cf.exploitable)
            needs_review = not is_tp and not is_fp

            severity = self._calc_severity(cf, combined)

            correlated = CorrelatedFinding(
                confirmed=cf,
                taint_confidence=taint_conf,
                llm_confidence=llm_conf,
                combined_confidence=round(combined, 2),
                is_true_positive=is_tp,
                needs_manual_review=needs_review,
                is_false_positive=is_fp,
                severity=severity,
            )
            results.append(correlated)
            log.debug(
                "fuser.result",
                vuln_class=cf.evaluated.taint_path.vuln_class,
                is_tp=is_tp,
                is_fp=is_fp,
                combined=combined,
            )
        return results

    def _calc_severity(self, cf: ConfirmedFinding, combined_confidence: float) -> str:
        base_severity = cf.evaluated.taint_path.sink.pattern.severity

        if not cf.exploitable:
            # Downgrade if LLM says not exploitable
            severity_order = ["info", "low", "medium", "high", "critical"]
            idx = severity_order.index(base_severity)
            base_severity = severity_order[max(0, idx - 2)]

        if combined_confidence < 0.4:
            return "low"
        if combined_confidence < 0.6:
            severity_map = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}
            return severity_map.get(base_severity, "info")

        return base_severity
