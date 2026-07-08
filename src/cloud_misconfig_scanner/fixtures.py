from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .aws import AwsClients


class FixtureAwsError(Exception):
    def __init__(self, code: str, message: str | None = None):
        self.response = {"Error": {"Code": code, "Message": message or code}}
        super().__init__(message or code)


def _raise_if_error(response: Any) -> Any:
    if isinstance(response, dict) and "Error" in response:
        error = response["Error"]
        raise FixtureAwsError(error.get("Code", "FixtureError"), error.get("Message"))
    return response


class FixtureS3Client:
    def __init__(self, data: dict[str, Any]):
        self.data = data

    def list_buckets(self) -> dict[str, Any]:
        return self.data.get("list_buckets", {"Buckets": []})

    def _bucket_call(self, bucket: str, operation: str) -> dict[str, Any]:
        response = self.data.get("buckets", {}).get(bucket, {}).get(operation, {})
        return _raise_if_error(response)

    def get_bucket_acl(self, Bucket: str) -> dict[str, Any]:
        return self._bucket_call(Bucket, "get_bucket_acl")

    def get_bucket_policy(self, Bucket: str) -> dict[str, Any]:
        return self._bucket_call(Bucket, "get_bucket_policy")

    def get_bucket_policy_status(self, Bucket: str) -> dict[str, Any]:
        return self._bucket_call(Bucket, "get_bucket_policy_status")

    def get_public_access_block(self, Bucket: str) -> dict[str, Any]:
        return self._bucket_call(Bucket, "get_public_access_block")

    def get_bucket_encryption(self, Bucket: str) -> dict[str, Any]:
        return self._bucket_call(Bucket, "get_bucket_encryption")


class FixtureIAMClient:
    def __init__(self, data: dict[str, Any]):
        self.data = data

    def list_users(self) -> dict[str, Any]:
        return {"Users": self.data.get("users", [])}

    def list_roles(self) -> dict[str, Any]:
        return {"Roles": self.data.get("roles", [])}

    def list_groups(self) -> dict[str, Any]:
        return {"Groups": self.data.get("groups", [])}

    def list_attached_user_policies(self, UserName: str) -> dict[str, Any]:
        user = self._identity("users", "UserName", UserName)
        return {"AttachedPolicies": user.get("AttachedPolicies", [])}

    def list_attached_role_policies(self, RoleName: str) -> dict[str, Any]:
        role = self._identity("roles", "RoleName", RoleName)
        return {"AttachedPolicies": role.get("AttachedPolicies", [])}

    def list_attached_group_policies(self, GroupName: str) -> dict[str, Any]:
        group = self._identity("groups", "GroupName", GroupName)
        return {"AttachedPolicies": group.get("AttachedPolicies", [])}

    def list_user_policies(self, UserName: str) -> dict[str, Any]:
        user = self._identity("users", "UserName", UserName)
        return {"PolicyNames": list(user.get("InlinePolicies", {}))}

    def list_role_policies(self, RoleName: str) -> dict[str, Any]:
        role = self._identity("roles", "RoleName", RoleName)
        return {"PolicyNames": list(role.get("InlinePolicies", {}))}

    def list_group_policies(self, GroupName: str) -> dict[str, Any]:
        group = self._identity("groups", "GroupName", GroupName)
        return {"PolicyNames": list(group.get("InlinePolicies", {}))}

    def get_user_policy(self, UserName: str, PolicyName: str) -> dict[str, Any]:
        user = self._identity("users", "UserName", UserName)
        return {"PolicyDocument": user.get("InlinePolicies", {})[PolicyName]}

    def get_role_policy(self, RoleName: str, PolicyName: str) -> dict[str, Any]:
        role = self._identity("roles", "RoleName", RoleName)
        return {"PolicyDocument": role.get("InlinePolicies", {})[PolicyName]}

    def get_group_policy(self, GroupName: str, PolicyName: str) -> dict[str, Any]:
        group = self._identity("groups", "GroupName", GroupName)
        return {"PolicyDocument": group.get("InlinePolicies", {})[PolicyName]}

    def get_policy(self, PolicyArn: str) -> dict[str, Any]:
        policy = self.data.get("policies", {})[PolicyArn]
        return {
            "Policy": {
                "Arn": PolicyArn,
                "DefaultVersionId": policy.get("DefaultVersionId", "v1"),
                "PolicyName": policy.get("PolicyName", PolicyArn.rsplit("/", 1)[-1]),
            }
        }

    def get_policy_version(self, PolicyArn: str, VersionId: str) -> dict[str, Any]:
        policy = self.data.get("policies", {})[PolicyArn]
        versions = policy.get("Versions", {})
        document = versions.get(VersionId, policy.get("Document", {}))
        return {"PolicyVersion": {"Document": document}}

    def _identity(self, collection: str, key: str, name: str) -> dict[str, Any]:
        for identity in self.data.get(collection, []):
            if identity.get(key) == name:
                return identity
        raise FixtureAwsError("NoSuchEntity", f"{collection}:{name}")


def load_fixture_clients(path: Path) -> AwsClients:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return AwsClients(
        s3=FixtureS3Client(payload.get("s3", {})),
        iam=FixtureIAMClient(payload.get("iam", {})),
        account_id=payload.get("account_id"),
    )
