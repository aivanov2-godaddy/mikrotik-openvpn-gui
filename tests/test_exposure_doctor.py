import unittest

from exposure_doctor import exposure_doctor_snapshot


class ExposureDoctorTests(unittest.TestCase):
    def inputs(self):
        return {
            "account": {"name": "router-admin-private", "group": "custom-private", "disabled": "no",
                        "address": "10.22.0.0/24", "password": "do-not-return"},
            "group": {"name": "custom-private", "policy": "read,rest-api,api,write,!policy", "comment": "private-note"},
            "services": [
                {"name": "www", "disabled": "no", "address": "", "certificate": "none", "port": "80"},
                {"name": "www-ssl", "disabled": "no", "address": "10.22.0.0/24", "certificate": "private-cert-name"},
                {"name": "api", "disabled": "yes", "address": "", "certificate": "none"},
                {"name": "api-ssl", "disabled": "no", "address": "10.22.0.0/24", "certificate": "private-cert-name"},
            ],
        }

    def test_exposure_is_derived_redacted_and_version_tolerant(self):
        result = exposure_doctor_snapshot(**self.inputs(), checked_at=123)
        checks = {item["id"]: item for item in result["checks"]}
        self.assertTrue(result["read_only"])
        self.assertEqual(result["checked_at"], 123)
        self.assertEqual(checks["account-source"]["status"], "verified")
        self.assertEqual(checks["service-www"]["status"], "warning")
        self.assertIn("unencrypted", checks["service-www"]["message"])
        self.assertEqual(checks["service-api-ssl"]["status"], "verified")
        self.assertEqual(checks["unrecognized-policy-flags"]["status"], "verified")
        self.assertIn("broad RouterOS configuration changes (write) is enabled", checks["feature-access"]["message"])
        self.assertIn("RouterOS user/group policy management (policy) is not enabled", checks["feature-access"]["message"])
        serialized = str(result)
        for private_value in ("router-admin-private", "custom-private", "10.22.0.0/24", "do-not-return", "private-note", "private-cert-name", "'port':", "'80'"):
            self.assertNotIn(private_value, serialized)

    def test_missing_version_dependent_properties_are_unknown_not_pass(self):
        result = exposure_doctor_snapshot(
            account={"group": "legacy"},
            group={"policy": None},
            services=[{"name": "www-ssl"}],
            checked_at=123,
        )
        checks = {item["id"]: item for item in result["checks"]}
        self.assertEqual(checks["account-source"]["status"], "unknown")
        self.assertEqual(checks["group-policies"]["status"], "unknown")
        self.assertEqual(checks["service-www-ssl"]["status"], "unknown")
        self.assertEqual(checks["service-api-ssl"]["status"], "unknown")
        self.assertEqual(checks["unrecognized-policy-flags"]["status"], "unknown")

    def test_current_available_from_service_field_is_derived_and_redacted(self):
        values = self.inputs()
        values["services"] = [
            {"name": "api-ssl", "disabled": "no", "available-from": "10.22.0.0/24", "certificate": "private-cert-name"},
        ]
        result = exposure_doctor_snapshot(**values)
        checks = {item["id"]: item for item in result["checks"]}
        self.assertEqual(checks["service-api-ssl"]["status"], "verified")
        self.assertNotIn("10.22.0.0/24", str(result))
        self.assertNotIn("private-cert-name", str(result))

    def test_unavailable_and_unsupported_sources_remain_distinct(self):
        result = exposure_doctor_snapshot(
            account=None, group=None, services=None,
            source_status={"account": "unsupported", "group": "unknown", "services": "unsupported"},
        )
        checks = {item["id"]: item for item in result["checks"]}
        self.assertEqual(checks["account"]["status"], "unsupported")
        self.assertEqual(checks["group-policies"]["status"], "unknown")
        self.assertEqual(checks["management-services"]["status"], "unsupported")
        self.assertEqual(checks["firewall-boundary"]["status"], "unknown")

    def test_unrecognized_routeros_policy_flags_make_posture_unknown_without_echoing_values(self):
        values = self.inputs()
        values["group"]["policy"] = "read,api,rest-api,policy-nextgen"
        result = exposure_doctor_snapshot(**values)
        checks = {item["id"]: item for item in result["checks"]}
        self.assertEqual(checks["unrecognized-policy-flags"]["status"], "unknown")
        self.assertIn("does not recognize", checks["unrecognized-policy-flags"]["message"])
        self.assertNotIn("policy-nextgen", str(result))
        self.assertNotIn("raw policy values", checks["unrecognized-policy-flags"]["message"])

    def test_negated_known_routeros_policies_do_not_trigger_unknown_flag(self):
        values = self.inputs()
        values["group"]["policy"] = "read,api,rest-api,!write,!policy,!ftp"
        result = exposure_doctor_snapshot(**values)
        checks = {item["id"]: item for item in result["checks"]}
        self.assertEqual(checks["unrecognized-policy-flags"]["status"], "verified")
        self.assertIn("broad RouterOS configuration changes (write) is not enabled", checks["feature-access"]["message"])
        self.assertNotIn("file-transfer-login", checks["high-impact-policies"]["message"])

    def test_all_address_catchalls_are_not_misreported_as_restricted(self):
        values = self.inputs()
        values["account"]["address"] = "10.22.0.0/24,::/0"
        result = exposure_doctor_snapshot(**values)
        check = next(item for item in result["checks"] if item["id"] == "account-source")
        self.assertEqual(check["status"], "warning")

    def test_address_scope_parsing_is_redacted_and_never_proves_firewall_boundary(self):
        cases = (
            ("192.0.2.8", "verified", "verified"),
            ("192.0.2.0/24,198.51.100.4", "verified", "verified"),
            ("2001:db8::1", "verified", "verified"),
            ("2001:db8:1::/48,2001:db8:2::5", "verified", "verified"),
            ("not-an-address", "unknown", "unknown"),
            ("192.0.2.0/24,not-an-address", "unknown", "unknown"),
            ("0.0.0.0/0", "warning", "warning"),
            ("::/0", "warning", "warning"),
        )
        for address, account_status, service_status in cases:
            with self.subTest(address=address):
                values = self.inputs()
                values["account"]["address"] = address
                values["services"][0]["name"] = "ssh"
                values["services"][0]["address"] = address
                result = exposure_doctor_snapshot(**values)
                checks = {item["id"]: item for item in result["checks"]}
                self.assertEqual(checks["account-source"]["status"], account_status)
                self.assertEqual(checks["service-ssh"]["status"], service_status)
                self.assertEqual(checks["firewall-boundary"]["status"], "unknown")
                self.assertNotIn(address, str(result))

    def test_observed_management_peer_is_compared_to_account_and_rest_service_filters(self):
        values = self.inputs()
        values["account"]["address"] = "10.22.0.0/24,192.0.2.10-192.0.2.20"
        values["services"][0].update({
            "name": "www-ssl", "disabled": "no", "available-from": "2001:db8::/48",
        })
        result = exposure_doctor_snapshot(
            **values, active_source="192.0.2.15", active_source_status="verified",
            rest_service="www-ssl", checked_at=123,
        )
        checks = {item["id"]: item for item in result["checks"]}
        self.assertEqual(checks["account-source-match"]["status"], "verified")
        self.assertIn("matches", checks["account-source-match"]["message"])
        self.assertEqual(checks["management-service-source-match"]["status"], "warning")
        self.assertIn("does not match", checks["management-service-source-match"]["message"])
        self.assertEqual(checks["firewall-boundary"]["status"], "unknown")
        self.assertNotIn("192.0.2.15", str(result))

    def test_ipv6_source_match_and_ambiguous_peer_remain_redacted_or_unknown(self):
        values = self.inputs()
        values["account"]["address"] = "2001:db8:100::/48"
        matched = exposure_doctor_snapshot(
            **values, active_source="2001:db8:100::42", active_source_status="verified",
            checked_at=123,
        )
        checks = {item["id"]: item for item in matched["checks"]}
        self.assertEqual(checks["account-source-match"]["status"], "verified")
        self.assertNotIn("2001:db8:100::42", str(matched))

        unknown = exposure_doctor_snapshot(
            **values, active_source=None, active_source_status="unknown", checked_at=123,
        )
        unknown_checks = {item["id"]: item for item in unknown["checks"]}
        self.assertEqual(unknown_checks["account-source-match"]["status"], "unknown")
        self.assertEqual(unknown_checks["management-service-source-match"]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
