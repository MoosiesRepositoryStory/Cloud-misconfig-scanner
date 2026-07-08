from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AwsClients:
    s3: Any
    iam: Any
    account_id: str | None


def create_boto3_clients(profile: str | None = None, region: str | None = None) -> AwsClients:
    """Create live AWS clients lazily so tests and fixture mode do not require boto3."""
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError(
            "boto3 is required for live AWS scans. Install the project with `pip install -e .` "
            "or run with `--fixture`."
        ) from exc

    session_kwargs: dict[str, str] = {}
    if profile:
        session_kwargs["profile_name"] = profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)
    account_id = None
    try:
        account_id = session.client("sts").get_caller_identity().get("Account")
    except Exception:
        account_id = None

    return AwsClients(
        s3=session.client("s3"),
        iam=session.client("iam"),
        account_id=account_id,
    )
