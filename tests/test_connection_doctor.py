import unittest

from connection_doctor import connection_doctor_snapshot


class ConnectionDoctorTests(unittest.TestCase):
    def inputs(self):
        return {
            "username": "user-one",
            "router": {"version": "7.24.4 (stable)", "free-memory": "123"},
            "server": {"name": "ovpn", "enabled": True, "protocol": "udp", "cipher": "aes256-gcm", "auth": "sha256", "redirect_gateway": "def1"},
            "users": [{"name": "user-one", "disabled": False, "password": "never return this"}],
            "sessions": [{"name": "user-one", "service": "ovpn", "address": "10.0.0.2"}],
        }

    def test_confirmed_session_and_capability_report_is_redacted(self) -> None:
        result = connection_doctor_snapshot(**self.inputs())
        checks = {item["id"]: item for item in result["checks"]}
        self.assertEqual(checks["router"]["status"], "pass")
        self.assertEqual(checks["session"]["status"], "pass")
        self.assertEqual(checks["routes"]["status"], "pass")
        self.assertEqual(checks["compatibility"]["status"], "pass")
        self.assertTrue(all(item["source"] and item["checked_at"] for item in checks.values()))
        self.assertTrue(all(item["confidence"] in {"high", "medium", "low", "none"} for item in checks.values()))
        serialized = str(result)
        self.assertNotIn("user-one", serialized)
        self.assertNotIn("never return this", serialized)
        self.assertNotIn("10.0.0.2", serialized)

    def test_offline_partial_and_malformed_data_fail_closed_to_unknown(self) -> None:
        offline = connection_doctor_snapshot(username="user-one", router=None, server=None, users=None, sessions=None)
        self.assertEqual(offline["overall"], "unavailable")
        partial = self.inputs()
        partial.update(router={"version": "not-a-version"}, server=None, users=None, sessions=None)
        result = connection_doctor_snapshot(**partial)
        checks = {item["id"]: item for item in result["checks"]}
        self.assertEqual(checks["router"]["status"], "unknown")
        self.assertEqual(checks["server"]["status"], "unknown")
        self.assertEqual(checks["account"]["status"], "unknown")
        self.assertEqual(checks["session"]["status"], "unknown")
        self.assertEqual(checks["compatibility"]["status"], "unknown")

    def test_unsupported_protocol_disabled_user_and_no_session_are_distinguished(self) -> None:
        values = self.inputs()
        values["router"] = {"version": "6.49.17"}
        values["users"] = [{"name": "user-one", "disabled": True}]
        values["sessions"] = []
        result = connection_doctor_snapshot(**values)
        checks = {item["id"]: item for item in result["checks"]}
        self.assertEqual(checks["compatibility"]["status"], "error")
        self.assertEqual(checks["account"]["status"], "error")
        self.assertEqual(checks["session"]["status"], "warning")

    def test_stale_observation_is_marked_stale(self) -> None:
        values = self.inputs()
        result = connection_doctor_snapshot(**values, checked_at=1)
        self.assertEqual(result["overall"], "stale")
        self.assertTrue(all(item["freshness"] == "stale" for item in result["checks"]))

    def test_gcm_with_non_null_auth_is_version_aware(self) -> None:
        values = self.inputs()
        values["router"] = {"version": "7.15.3"}
        result = connection_doctor_snapshot(**values)
        compatibility = next(item for item in result["checks"] if item["id"] == "compatibility")
        self.assertEqual(compatibility["status"], "warning")
        self.assertIn("GCM", compatibility["message"])


if __name__ == "__main__":
    unittest.main()
