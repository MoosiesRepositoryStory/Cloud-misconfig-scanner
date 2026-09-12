from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .aws import create_boto3_clients
from .findings import Severity
from .fixtures import load_fixture_clients
from .iam import scan_iam
from .report import findings_to_json, render_table
from .s3 import scan_s3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-misconfig-scanner",
        description="Read-only AWS security scanner for S3 and IAM misconfigurations.",
    )
    parser.add_argument("--profile", help="AWS profile name for live Boto3 scans.")
    parser.add_argument("--region", help="AWS region for live Boto3 scans.")
    parser.add_argument(
        "--fixture",
        type=Path,
        help="Scan a local JSON fixture instead of calling AWS.",
    )
    parser.add_argument(
        "--services",
        default="s3,iam",
        help="Comma-separated services to scan. Supported: s3, iam. Default: s3,iam.",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format. Default: table.",
    )
    parser.add_argument("--output", type=Path, help="Optional path to write the report.")
    parser.add_argument(
        "--fail-on",
        choices=[severity.name for severity in Severity],
        help="Exit with code 2 when any finding is at least this severity.",
    )
    parser.add_argument(
        "--include-aws-managed",
        action="store_true",
        help="Also evaluate AWS-managed IAM policies attached to identities.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    services = {service.strip().lower() for service in args.services.split(",") if service.strip()}
    unsupported = services - {"s3", "iam"}
    if unsupported:
        parser.error(f"unsupported services: {', '.join(sorted(unsupported))}")

    if args.fixture:
        clients = load_fixture_clients(args.fixture)
    else:
        try:
            clients = create_boto3_clients(profile=args.profile, region=args.region)
        except RuntimeError as exc:
            parser.error(str(exc))

    findings = []
    if "s3" in services:
        findings.extend(scan_s3(clients.s3, account_id=clients.account_id))
    if "iam" in services:
        findings.extend(
            scan_iam(
                clients.iam,
                account_id=clients.account_id,
                include_aws_managed=args.include_aws_managed,
            )
        )

    findings.sort(key=lambda finding: (-finding.severity.value, finding.service, finding.resource))

    report = findings_to_json(findings) if args.format == "json" else render_table(findings)
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)

    if args.fail_on:
        threshold = Severity[args.fail_on]
        if any(finding.severity >= threshold for finding in findings):
            return 2
    return 0
