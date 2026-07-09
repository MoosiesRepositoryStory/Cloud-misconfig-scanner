Render Link: https://cloud-misconfig-scanner.onrender.com/
# Cloud Misconfiguration Scanner

An advanced, read-only AWS security automation project that uses Boto3-style API responses to detect high-value cloud misconfigurations:

- Public S3 buckets
- S3 buckets without default server-side encryption
- Weak IAM identity policies
- Public IAM role trust policies

The scanner is designed around JSON-heavy AWS responses. The detection logic is separated from Boto3 clients, so it can run against a real AWS account or against a local fixture for safe testing and demos.

## Live Demo

Run the Flask dashboard in `dashboard/` to scan local fixtures and view S3/IAM findings in a browser severity dashboard.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Run against the included sample AWS response fixture:

```powershell
python -m cloud_misconfig_scanner --fixture examples/aws_responses.sample.json --format table
python -m cloud_misconfig_scanner --fixture examples/aws_responses.sample.json --format json
```

Run against AWS with your configured credentials:

```powershell
python -m cloud_misconfig_scanner --profile prod-readonly --region us-east-1
```

Fail CI if high-risk findings are present:

```powershell
python -m cloud_misconfig_scanner --profile prod-readonly --fail-on HIGH
```

## Required AWS Permissions

Use a read-only principal. The scanner needs these permissions for the implemented checks:

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

Run the tests:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests
```

The project avoids network access in tests by using fake clients and fixture clients that mimic the subset of AWS JSON responses the scanner consumes.
