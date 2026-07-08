from __future__ import annotations

import json
from typing import Iterable

from .findings import Finding


def findings_to_json(findings: Iterable[Finding]) -> str:
    return json.dumps([finding.to_dict() for finding in findings], indent=2, sort_keys=True)


def render_table(findings: list[Finding]) -> str:
    if not findings:
        return "No misconfigurations found."

    headers = ["Severity", "Service", "Check", "Resource", "Title"]
    rows = [
        [
            finding.severity.name,
            finding.service,
            finding.check_id,
            finding.resource,
            finding.title,
        ]
        for finding in findings
    ]

    widths = [
        min(max(len(str(row[index])) for row in [headers] + rows), max_width)
        for index, max_width in enumerate([10, 8, 34, 42, 70])
    ]

    def cell(value: str, index: int) -> str:
        text = str(value)
        width = widths[index]
        if len(text) > width:
            text = text[: width - 1] + "..."
        return text.ljust(width)

    lines = [
        " | ".join(cell(header, index) for index, header in enumerate(headers)),
        "-+-".join("-" * width for width in widths),
    ]
    for row in rows:
        lines.append(" | ".join(cell(value, index) for index, value in enumerate(row)))
    return "\n".join(lines)
