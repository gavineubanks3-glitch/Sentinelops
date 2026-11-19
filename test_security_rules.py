
import unittest
from security_rules import analyze_resource


class TestSecurityRules(unittest.TestCase):

    def test_public_storage_is_high_risk(self):
        resource = {
            "name": "test-storage",
            "type": "storage",
            "public_access": True,
            "encryption_enabled": True,
            "logging_enabled": True
        }

        findings = analyze_resource(resource)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("public access", findings[0]["finding"])

    def test_unencrypted_storage_is_high_risk(self):
        resource = {
            "name": "test-storage",
            "type": "storage",
            "public_access": False,
            "encryption_enabled": False,
            "logging_enabled": True
        }

        findings = analyze_resource(resource)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_disabled_logging_is_medium_risk(self):
        resource = {
            "name": "test-storage",
            "type": "storage",
            "public_access": False,
            "encryption_enabled": True,
            "logging_enabled": False
        }

        findings = analyze_resource(resource)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_unrestricted_firewall_is_high_risk(self):
        resource = {
            "name": "test-firewall",
            "type": "firewall",
            "unrestricted_inbound": True
        }

        findings = analyze_resource(resource)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_secure_storage_has_no_findings(self):
        resource = {
            "name": "secure-storage",
            "type": "storage",
            "public_access": False,
            "encryption_enabled": True,
            "logging_enabled": True
        }

        findings = analyze_resource(resource)

        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()

