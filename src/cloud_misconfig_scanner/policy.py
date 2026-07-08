from __future__ import annotations

import fnmatch
import json
from typing import Any
from urllib.parse import unquote


SENSITIVE_SERVICE_WILDCARDS = {
    "iam:*",
    "sts:*",
    "organizations:*",
    "account:*",
    "s3:*",
    "ec2:*",
    "lambda:*",
    "kms:*",
    "secretsmanager:*",
}

PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:CreatePolicyVersion",
    "iam:PassRole",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "sts:AssumeRole",
}

PUBLIC_PRINCIPAL_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def parse_policy_document(document: Any) -> dict[str, Any]:
    if document is None:
        return {}
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        text = document.strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return json.loads(unquote(text))
    return {}


def statements(document: Any) -> list[dict[str, Any]]:
    parsed = parse_policy_document(document)
    raw_statements = parsed.get("Statement", [])
    if isinstance(raw_statements, dict):
        return [raw_statements]
    return [statement for statement in raw_statements if isinstance(statement, dict)]


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def string_list(value: Any) -> list[str]:
    return [item for item in as_list(value) if isinstance(item, str)]


def is_allow(statement: dict[str, Any]) -> bool:
    return str(statement.get("Effect", "")).lower() == "allow"


def has_resource_wildcard(statement: dict[str, Any]) -> bool:
    resources = string_list(statement.get("Resource"))
    not_resources = string_list(statement.get("NotResource"))
    return "*" in resources or not_resources == ["*"]


def action_matches(action: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def statement_allows_action(statement: dict[str, Any], patterns: set[str]) -> bool:
    actions = string_list(statement.get("Action"))
    if "*" in actions:
        return True
    return any(action_matches(action, pattern) for action in actions for pattern in patterns)


def action_contains_wildcard(action: str) -> bool:
    return "*" in action or "?" in action


def statement_has_service_wildcard(statement: dict[str, Any], patterns: set[str]) -> bool:
    actions = string_list(statement.get("Action"))
    return any(
        action_contains_wildcard(action) and action_matches(action, pattern)
        for action in actions
        for pattern in patterns
    )


def principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, list):
        return any(principal_is_public(item) for item in principal)
    if isinstance(principal, dict):
        return any(principal_is_public(value) for value in principal.values())
    return False


def acl_grant_is_public(grant: dict[str, Any]) -> bool:
    grantee = grant.get("Grantee", {})
    return grantee.get("URI") in PUBLIC_PRINCIPAL_URIS


def find_weak_identity_policy_statements(document: Any, source: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for index, statement in enumerate(statements(document)):
        if not is_allow(statement):
            continue

        actions = string_list(statement.get("Action"))
        not_actions = string_list(statement.get("NotAction"))
        resources = string_list(statement.get("Resource"))

        base = {
            "source": source,
            "statement_index": index,
            "sid": statement.get("Sid"),
            "actions": actions,
            "not_actions": not_actions,
            "resources": resources,
        }

        if not_actions and has_resource_wildcard(statement):
            issues.append(
                base
                | {
                    "check_id": "IAM_BROAD_NOT_ACTION",
                    "severity": "CRITICAL",
                    "title": "Policy uses broad NotAction on all resources",
                    "description": "An Allow statement with NotAction and wildcard resources can grant nearly unrestricted access.",
                }
            )
            continue

        if "*" in actions and has_resource_wildcard(statement):
            issues.append(
                base
                | {
                    "check_id": "IAM_ADMIN_WILDCARD",
                    "severity": "CRITICAL",
                    "title": "Policy grants administrator wildcard access",
                    "description": "The policy allows every action on every resource.",
                }
            )
            continue

        if has_resource_wildcard(statement):
            matched_services = sorted(
                pattern
                for pattern in SENSITIVE_SERVICE_WILDCARDS
                if statement_has_service_wildcard(statement, {pattern})
            )
            if matched_services:
                issues.append(
                    base
                    | {
                        "check_id": "IAM_SERVICE_WILDCARD",
                        "severity": "HIGH",
                        "title": "Policy grants sensitive service wildcard access",
                        "description": "The policy grants broad access to sensitive cloud services on all resources.",
                        "matched_patterns": matched_services,
                    }
                )
                continue

            matched_actions = sorted(
                action
                for action in PRIVILEGE_ESCALATION_ACTIONS
                if statement_allows_action(statement, {action})
            )
            if matched_actions:
                issues.append(
                    base
                    | {
                        "check_id": "IAM_PRIVILEGE_ESCALATION",
                        "severity": "HIGH",
                        "title": "Policy grants risky privilege-escalation actions",
                        "description": "The policy allows identity, role-passing, or code-deployment actions on all resources.",
                        "matched_actions": matched_actions,
                    }
                )

    return issues


def find_public_trust_statements(document: Any, source: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for index, statement in enumerate(statements(document)):
        if not is_allow(statement):
            continue
        if not principal_is_public(statement.get("Principal")):
            continue
        if not statement_allows_action(statement, {"sts:AssumeRole", "*"}):
            continue
        issues.append(
            {
                "source": source,
                "statement_index": index,
                "sid": statement.get("Sid"),
                "principal": statement.get("Principal"),
                "actions": string_list(statement.get("Action")),
            }
        )
    return issues


def find_public_s3_policy_statements(document: Any, source: str) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for index, statement in enumerate(statements(document)):
        if not is_allow(statement):
            continue
        if not principal_is_public(statement.get("Principal")):
            continue
        if not statement_allows_action(statement, {"s3:GetObject", "s3:*", "*"}):
            continue
        issues.append(
            {
                "source": source,
                "statement_index": index,
                "sid": statement.get("Sid"),
                "principal": statement.get("Principal"),
                "actions": string_list(statement.get("Action")),
                "resources": string_list(statement.get("Resource")),
            }
        )
    return issues
