"""The Finding model.

Every finding NardTrace produces answers six questions: what was found, where
the evidence came from, what it means, what it does NOT establish, how
confident we are, and what to do next. Each finding also carries an evidence
status so confirmed evidence is never mixed up with third-party intelligence,
inferences, or things we could not determine.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    CONFIRMED = "CONFIRMED"            # Directly observed in the evidence itself
    EXTERNAL_INTEL = "EXTERNAL INTEL"  # Reported by a third-party source (RDAP, DNS, reputation APIs)
    ASSUMPTION = "ASSUMPTION"          # An inference / heuristic, could be wrong
    UNKNOWN = "UNKNOWN"                # Could not be determined (lookup failed, data absent)


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Finding:
    module: str
    title: str
    status: Status
    what_found: str
    source: str
    meaning: str
    not_established: str
    confidence: Confidence
    next_step: str
    severity: Severity = Severity.INFO
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["confidence"] = self.confidence.value
        d["severity"] = self.severity.value
        return d


def unknown(module: str, title: str, what: str, error: str, next_step: str,
            not_established: str = "Nothing — this check produced no result.") -> Finding:
    """Standard UNKNOWN finding for a failed or skipped lookup. Never fabricate a result."""
    return Finding(
        module=module,
        title=title,
        status=Status.UNKNOWN,
        what_found=what,
        source=f"Lookup error: {error}",
        meaning="This check could not be completed, so it neither supports nor rules out anything.",
        not_established=not_established,
        confidence=Confidence.LOW,
        next_step=next_step,
        severity=Severity.INFO,
        data={"error": error},
    )
