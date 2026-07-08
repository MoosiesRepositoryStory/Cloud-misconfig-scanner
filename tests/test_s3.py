import unittest

from cloud_misconfig_scanner.fixtures import FixtureS3Client
from cloud_misconfig_scanner.s3 import scan_s3


class S3ScannerTests(unittest.TestCase):
    def test_detects_public_bucket_and_missing_encryption(self):
        client = FixtureS3Client(
            {
                "list_buckets": {"Buckets": [{"Name": "data-prod"}]},
                "buckets": {
                    "data-prod": {
                        "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": True}},
                        "get_bucket_acl": {
                            "Grants": [
                                {
                                    "Grantee": {
                                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                                    },
                                    "Permission": "READ",
                                }
                            ]
                        },
                        "get_bucket_policy": {},
                        "get_public_access_block": {},
                        "get_bucket_encryption": {
                            "Error": {
                                "Code": "ServerSideEncryptionConfigurationNotFoundError"
                            }
                        },
                    }
                },
            }
        )

        findings = scan_s3(client)
        check_ids = {finding.check_id for finding in findings}

        self.assertIn("S3_PUBLIC_POLICY_STATUS", check_ids)
        self.assertIn("S3_PUBLIC_ACL", check_ids)
        self.assertIn("S3_DEFAULT_ENCRYPTION_DISABLED", check_ids)

    def test_access_denied_does_not_create_missing_config_findings(self):
        client = FixtureS3Client(
            {
                "list_buckets": {"Buckets": [{"Name": "restricted"}]},
                "buckets": {
                    "restricted": {
                        "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": False}},
                        "get_bucket_acl": {
                            "Error": {
                                "Code": "AccessDenied"
                            }
                        },
                        "get_bucket_policy": {
                            "Error": {
                                "Code": "AccessDenied"
                            }
                        },
                        "get_public_access_block": {
                            "Error": {
                                "Code": "AccessDenied"
                            }
                        },
                        "get_bucket_encryption": {
                            "Error": {
                                "Code": "AccessDenied"
                            }
                        },
                    }
                },
            }
        )

        findings = scan_s3(client)
        check_ids = {finding.check_id for finding in findings}

        self.assertNotIn("S3_PUBLIC_ACCESS_BLOCK_DISABLED", check_ids)
        self.assertNotIn("S3_DEFAULT_ENCRYPTION_DISABLED", check_ids)


if __name__ == "__main__":
    unittest.main()
