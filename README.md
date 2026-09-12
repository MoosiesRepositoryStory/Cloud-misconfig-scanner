# Cloud Misconfiguration Scanner

A read-only AWS security scanner that detects high-value S3 and IAM
misconfigurations from Boto3-shaped JSON responses — runs against a real
AWS account or a local fixture, so it's safe to demo without credentials.

**Live demo:** [cloud-misconfig-scanner.onrender.com](https://cloud-misconfig-scanner.onrender.com/)
(runs entirely against local fixtures — no AWS credentials, no network calls)

## What it detects

- Public S3 buckets (via ACL, bucket policy, or `PublicAccessBlock` status)
- S3 buckets without default server-side encryption
- Overprivileged IAM policies (wildcard actions/resources, broad `NotAction`,
  privilege-escalation-prone service grants)
- Public IAM role trust policies

Detection logic is separated from the Boto3 client, so the same checks run
identically against a real account or a fixture file — useful for CI and for
safe demos alike.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate   # .venv\Scripts\Activate.ps1 on Windows
pip install -e ".[dev]"
```

Run against the included sample fixture:

```bash
python -m cloud_misconfig_scanner --fixture examples/aws_responses.sample.json --format table
python -m cloud_misconfig_scanner --fixture examples/aws_responses.sample.json --format json
```

Run against a real AWS account with your configured credentials:

```bash
python -m cloud_misconfig_scanner --profile prod-readonly --region us-east-1
```

Fail CI if high-risk findings are present:

```bash
python -m cloud_misconfig_scanner --profile prod-readonly --fail-on HIGH
```

There's also a browser dashboard — see [`dashboard/README.md`](dashboard/README.md)
for a filterable findings table with JSON/CSV export, runnable as a web app
or a standalone desktop app (PyWebView).

## Required AWS permissions

Use a read-only principal. The scanner needs these permissions for the
implemented checks:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListGroups",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedGroupPolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:ListGroupPolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:GetGroupPolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
      ],
      "Resource": "*"
    }
  ]
}
```

## Checks

| Check ID | Severity | What it detects |
| --- | --- | --- |
| `S3_PUBLIC_POLICY_STATUS` | Critical | AWS says the bucket policy is public |
| `S3_PUBLIC_ACL` | Critical | ACL grants public or authenticated AWS users access |
| `S3_PUBLIC_POLICY` | Critical | Bucket policy allows public access |
| `S3_PUBLIC_ACCESS_BLOCK_DISABLED` | High | Bucket-level public access block is missing or incomplete |
| `S3_DEFAULT_ENCRYPTION_DISABLED` | High | Bucket has no default server-side encryption |
| `IAM_ADMIN_WILDCARD` | Critical | IAM policy allows `Action: "*"` on `Resource: "*"` |
| `IAM_BROAD_NOT_ACTION` | Critical | IAM policy uses broad `NotAction` with wildcard resources |
| `IAM_SERVICE_WILDCARD` | High | IAM policy grants sensitive service wildcards on all resources |
| `IAM_PRIVILEGE_ESCALATION` | High | IAM policy grants risky escalation actions on all resources |
| `IAM_PUBLIC_TRUST_POLICY` | Critical | Role trust policy can be assumed by any principal |

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

Tests avoid network access entirely, using fake and fixture-backed clients
that mimic the subset of AWS JSON responses the scanner consumes.

## Windows packaging

`package_windows.ps1` bundles the desktop dashboard into a standalone
`.exe` via PyInstaller, for distribution without a Python install.
