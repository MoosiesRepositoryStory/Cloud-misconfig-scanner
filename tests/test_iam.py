import unittest

from cloud_misconfig_scanner.fixtures import FixtureIAMClient
from cloud_misconfig_scanner.iam import scan_iam


class IamScannerTests(unittest.TestCase):
    def test_detects_public_role_trust_and_weak_policy(self):
        client = FixtureIAMClient(
            {
                "users": [],
                "groups": [],
                "roles": [
                    {
                        "RoleName": "public-admin",
                        "AssumeRolePolicyDocument": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": "*",
                                    "Action": "sts:AssumeRole",
                                }
                            ]
                        },
                        "InlinePolicies": {
                            "Admin": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "*",
                                        "Resource": "*",
                                    }
                                ]
                            }
                        },
                        "AttachedPolicies": [],
                    }
                ],
            }
        )

        findings = scan_iam(client)
        check_ids = {finding.check_id for finding in findings}

        self.assertIn("IAM_PUBLIC_TRUST_POLICY", check_ids)
        self.assertIn("IAM_ADMIN_WILDCARD", check_ids)


if __name__ == "__main__":
    unittest.main()
