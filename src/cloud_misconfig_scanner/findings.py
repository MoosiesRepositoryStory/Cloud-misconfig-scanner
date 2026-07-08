from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class Finding:
    service: str
    resource: str
    check_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    region: str | None = None
    account_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data
