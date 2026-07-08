import unittest

from cloud_misconfig_scanner.policy import (
    find_public_s3_policy_statements,
    find_weak_identity_policy_statements,
    parse_policy_document,
)


class PolicyParsingTests(unittest.TestCase):
    def test_parses_json_policy_string(self):
        parsed = parse_policy_document('{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}')

        self.assertEqual(parsed["Statement"]["Action"], "*")

    def test_detects_admin_wildcard_policy(self):
        issues = find_weak_identity_policy_statements(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ]
            },
            source="unit-test",
        )

        self.assertEqual(issues[0]["check_id"], "IAM_ADMIN_WILDCARD")

    def test_detects_broad_not_action_policy(self):
        issues = find_weak_identity_policy_statements(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "NotAction": "iam:DeleteUser",
                        "Resource": "*",
                    }
                ]
            },
            source="unit-test",
        )

        self.assertEqual(issues[0]["check_id"], "IAM_BROAD_NOT_ACTION")

    def test_detects_pass_role_as_privilege_escalation(self):
        issues = find_weak_identity_policy_statements(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "iam:PassRole",
                        "Resource": "*",
                    }
                ]
            },
            source="unit-test",
        )

        self.assertEqual(issues[0]["check_id"], "IAM_PRIVILEGE_ESCALATION")

    def test_detects_public_s3_read_policy(self):
        issues = find_public_s3_policy_statements(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::data-prod/*",
                    }
                ]
            },
            source="bucket-policy",
        )

        self.assertEqual(len(issues), 1)


if __name__ == "__main__":
    unittest.main()
