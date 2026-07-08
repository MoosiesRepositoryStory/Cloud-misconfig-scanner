from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from .findings import Finding, Severity
from .policy import (
    find_public_trust_statements,
    find_weak_identity_policy_statements,
    parse_policy_document,
)


def scan_iam(
    client: Any,
    account_id: str | None = None,
    include_aws_managed: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []

    for user in _list_items(client, "list_users", "Users"):
        user_name = user.get("UserName", "<unknown>")
        resource = f"iam:user/{user_name}"
        findings.extend(
            _scan_identity_policies(
                client,
                identity_type="user",
                identity_name=user_name,
                resource=resource,
                account_id=account_id,
                include_aws_managed=include_aws_managed,
            )
        )

    for group in _list_items(client, "list_groups", "Groups"):
        group_name = group.get("GroupName", "<unknown>")
        resource = f"iam:group/{group_name}"
        findings.extend(
            _scan_identity_policies(
                client,
                identity_type="group",
                identity_name=group_name,
                resource=resource,
                account_id=account_id,
                include_aws_managed=include_aws_managed,
            )
        )

    for role in _list_items(client, "list_roles", "Roles"):
        role_name = role.get("RoleName", "<unknown>")
        resource = f"iam:role/{role_name}"
        trust_document = role.get("AssumeRolePolicyDocument")
        if trust_document:
            findings.extend(_public_trust_findings(trust_document, resource, account_id))
        findings.extend(
            _scan_identity_policies(
                client,
                identity_type="role",
                identity_name=role_name,
                resource=resource,
                account_id=account_id,
                include_aws_managed=include_aws_managed,
            )
        )

    return findings


def _scan_identity_policies(
    client: Any,
    identity_type: str,
    identity_name: str,
    resource: str,
    account_id: str | None,
    include_aws_managed: bool,
) -> list[Finding]:
    findings: list[Finding] = []

    attached_method = f"list_attached_{identity_type}_policies"
    attached_param = _identity_param(identity_type)
    for attached in _list_items(
        client,
        attached_method,
        "AttachedPolicies",
        **{attached_param: identity_name},
    ):
        arn = attached.get("PolicyArn", "")
        if _is_aws_managed_policy(arn) and not include_aws_managed:
            continue
        document = _get_default_policy_document(client, arn)
        source = f"attached:{attached.get('PolicyName', arn)}"
        findings.extend(_weak_policy_findings(document, resource, source, account_id))

    inline_list_method = f"list_{identity_type}_policies"
    inline_get_method = f"get_{identity_type}_policy"
    for policy_name in _list_policy_names(
        client,
        inline_list_method,
        **{attached_param: identity_name},
    ):
        document = getattr(client, inline_get_method)(
            **{attached_param: identity_name, "PolicyName": policy_name}
        ).get("PolicyDocument", {})
        findings.extend(_weak_policy_findings(document, resource, f"inline:{policy_name}", account_id))

    return findings


def _weak_policy_findings(
    document: Any,
    resource: str,
    source: str,
    account_id: str | None,
) -> list[Finding]:
    findings: list[Finding] = []
    for issue in find_weak_identity_policy_statements(document, source=source):
        findings.append(
            Finding(
                service="IAM",
                resource=resource,
                check_id=issue["check_id"],
                severity=Severity[issue["severity"]],
                title=issue["title"],
                description=issue["description"],
                remediation="Replace broad wildcards with least-privilege actions and resource ARNs.",
                evidence=issue,
                account_id=account_id,
            )
        )
    return findings


def _public_trust_findings(document: Any, resource: str, account_id: str | None) -> list[Finding]:
    findings: list[Finding] = []
    for issue in find_public_trust_statements(document, source="assume-role-policy"):
        findings.append(
            Finding(
                service="IAM",
                resource=resource,
                check_id="IAM_PUBLIC_TRUST_POLICY",
                severity=Severity.CRITICAL,
                title="Role trust policy is public",
                description="The role trust policy allows sts:AssumeRole from any principal.",
                remediation="Restrict the trust policy Principal to specific AWS accounts, roles, or federated identities.",
                evidence=issue,
                account_id=account_id,
            )
        )
    return findings


def _get_default_policy_document(client: Any, policy_arn: str) -> dict[str, Any]:
    policy = client.get_policy(PolicyArn=policy_arn).get("Policy", {})
    version_id = policy.get("DefaultVersionId")
    if not version_id:
        return {}
    return client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id).get(
        "PolicyVersion", {}
    ).get("Document", {})


def _is_aws_managed_policy(policy_arn: str) -> bool:
    return ":aws:policy/" in policy_arn


def _identity_param(identity_type: str) -> str:
    return {
        "user": "UserName",
        "role": "RoleName",
        "group": "GroupName",
    }[identity_type]


def _list_items(client: Any, method_name: str, result_key: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
    if hasattr(client, "get_paginator"):
        try:
            paginator = client.get_paginator(method_name)
            for page in paginator.paginate(**kwargs):
                yield from page.get(result_key, [])
            return
        except Exception:
            pass

    method = getattr(client, method_name)
    marker_name = "Marker"
    request_kwargs = dict(kwargs)
    while True:
        page = method(**request_kwargs)
        yield from page.get(result_key, [])
        if not page.get("IsTruncated"):
            break
        marker = page.get("Marker") or page.get("NextMarker")
        if not marker:
            break
        request_kwargs[marker_name] = marker


def _list_policy_names(client: Any, method_name: str, **kwargs: Any) -> Iterator[str]:
    for name_entry in _list_items(client, method_name, "PolicyNames", **kwargs):
        if isinstance(name_entry, str):
            yield name_entry


def parse_iam_policy_document(document: Any) -> dict[str, Any]:
    """Public helper for callers that only need AWS policy JSON parsing."""
    return parse_policy_document(document)
