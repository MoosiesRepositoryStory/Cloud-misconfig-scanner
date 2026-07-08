from __future__ import annotations

from typing import Any

from .findings import Finding, Severity
from .policy import acl_grant_is_public, find_public_s3_policy_statements


PUBLIC_ACL_PERMISSIONS = {"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}
PUBLIC_ACCESS_BLOCK_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


def scan_s3(client: Any, account_id: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in client.list_buckets().get("Buckets", []):
        bucket_name = bucket.get("Name")
        if not bucket_name:
            continue
        resource = f"s3://{bucket_name}"
        findings.extend(_scan_bucket_public_access(client, bucket_name, resource, account_id))
        findings.extend(_scan_bucket_encryption(client, bucket_name, resource, account_id))
    return findings


def _scan_bucket_public_access(
    client: Any,
    bucket_name: str,
    resource: str,
    account_id: str | None,
) -> list[Finding]:
    findings: list[Finding] = []

    policy_status = _safe_call(client.get_bucket_policy_status, Bucket=bucket_name)
    if policy_status.get("PolicyStatus", {}).get("IsPublic") is True:
        findings.append(
            Finding(
                service="S3",
                resource=resource,
                check_id="S3_PUBLIC_POLICY_STATUS",
                severity=Severity.CRITICAL,
                title="Bucket policy is public",
                description="AWS reports this bucket policy as public.",
                remediation="Remove public principals from the bucket policy and enable S3 Block Public Access.",
                evidence=policy_status,
                account_id=account_id,
            )
        )

    acl = _safe_call(client.get_bucket_acl, Bucket=bucket_name)
    public_grants = [
        {
            "grantee": grant.get("Grantee", {}),
            "permission": grant.get("Permission"),
        }
        for grant in acl.get("Grants", [])
        if acl_grant_is_public(grant) and grant.get("Permission") in PUBLIC_ACL_PERMISSIONS
    ]
    if public_grants:
        findings.append(
            Finding(
                service="S3",
                resource=resource,
                check_id="S3_PUBLIC_ACL",
                severity=Severity.CRITICAL,
                title="Bucket ACL grants public access",
                description="The bucket ACL grants access to AllUsers or AuthenticatedUsers.",
                remediation="Remove public ACL grants and prefer bucket-owner-enforced object ownership.",
                evidence={"public_grants": public_grants},
                account_id=account_id,
            )
        )

    bucket_policy = _safe_call(client.get_bucket_policy, Bucket=bucket_name)
    policy_document = bucket_policy.get("Policy")
    if policy_document:
        for issue in find_public_s3_policy_statements(policy_document, source="bucket-policy"):
            findings.append(
                Finding(
                    service="S3",
                    resource=resource,
                    check_id="S3_PUBLIC_POLICY",
                    severity=Severity.CRITICAL,
                    title="Bucket policy allows public object access",
                    description="The bucket policy has an Allow statement for a public principal.",
                    remediation="Restrict Principal and Resource in the bucket policy to trusted identities only.",
                    evidence=issue,
                    account_id=account_id,
                )
            )

    public_access_block = _safe_call(client.get_public_access_block, Bucket=bucket_name)
    public_access_block_error = public_access_block.get("_error")
    if public_access_block_error in {"AccessDenied", "NoSuchBucket"}:
        missing_flags = []
        config = {}
    else:
        config = public_access_block.get("PublicAccessBlockConfiguration", {})
        missing_flags = [flag for flag in PUBLIC_ACCESS_BLOCK_FLAGS if config.get(flag) is not True]
    if missing_flags:
        findings.append(
            Finding(
                service="S3",
                resource=resource,
                check_id="S3_PUBLIC_ACCESS_BLOCK_DISABLED",
                severity=Severity.HIGH,
                title="Bucket public access block is incomplete",
                description="One or more S3 bucket-level public access block controls are disabled or missing.",
                remediation="Enable all four S3 Block Public Access settings at the bucket or account level.",
                evidence={"missing_or_disabled": missing_flags, "configuration": config},
                account_id=account_id,
            )
        )

    return findings


def _scan_bucket_encryption(
    client: Any,
    bucket_name: str,
    resource: str,
    account_id: str | None,
) -> list[Finding]:
    encryption = _safe_call(client.get_bucket_encryption, Bucket=bucket_name)
    encryption_error = encryption.get("_error")
    if encryption_error in {"AccessDenied", "NoSuchBucket"}:
        return []

    rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    if rules:
        return []

    return [
        Finding(
            service="S3",
            resource=resource,
            check_id="S3_DEFAULT_ENCRYPTION_DISABLED",
            severity=Severity.HIGH,
            title="Bucket default encryption is disabled",
            description="The bucket has no default server-side encryption configuration.",
            remediation="Enable default server-side encryption with SSE-S3 or AWS KMS.",
            evidence={"aws_error": encryption.get("_error"), "rules": rules},
            account_id=account_id,
        )
    ]


def _safe_call(func: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        response = func(**kwargs)
        return response if isinstance(response, dict) else {}
    except Exception as exc:
        code = _aws_error_code(exc)
        if code in {
            "NoSuchBucketPolicy",
            "NoSuchPublicAccessBlockConfiguration",
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchBucket",
            "AccessDenied",
        }:
            return {"_error": code}
        return {"_error": code}


def _aws_error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code:
            return str(code)
    return exc.__class__.__name__
