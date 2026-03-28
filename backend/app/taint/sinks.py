# Taint sink definitions — re-exported from trust_boundaries for clarity
from app.ingestion.trust_boundaries import TAINT_SINKS, SinkPattern

__all__ = ["TAINT_SINKS", "SinkPattern"]
