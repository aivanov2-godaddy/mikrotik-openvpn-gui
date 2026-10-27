import logging
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from config import ConfigurationError, RuntimeConfig
from integrations import RedisStreamPublisher


class _FakeRedis:
    def xadd(self, *args, **kwargs):
        return "1-0"


class RedisTransportSecurityTests(unittest.TestCase):
    def test_configuration_keeps_both_private_and_tls_schemes_supported(self) -> None:
        plain = "redis://vpn-dashboard:secret@redis.internal:6379/0"
        tls = "rediss://vpn-dashboard:secret@redis.internal:6380/0"

        self.assertEqual(RuntimeConfig.from_environ({"REDIS_STREAM_URL": plain}).redis_stream_url, plain)
        self.assertEqual(RuntimeConfig.from_environ({"REDIS_STREAM_URL": tls}).redis_stream_url, tls)

    def test_invalid_scheme_diagnostic_distinguishes_plaintext_and_tls(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "plaintext transport.*TLS transport"):
            RuntimeConfig.from_environ({"REDIS_STREAM_URL": "https://redis.internal"})

    def test_plaintext_transport_warns_without_logging_url_or_credentials(self) -> None:
        url = "redis://vpn-dashboard:secret-value@private-redis.internal:6379/0"
        redis_module = SimpleNamespace(Redis=SimpleNamespace(from_url=mock.Mock(return_value=_FakeRedis())))

        with mock.patch.dict(sys.modules, {"redis": redis_module}):
            with self.assertLogs("integrations", level=logging.WARNING) as captured:
                publisher = RedisStreamPublisher(url)

        message = "\n".join(captured.output)
        self.assertIn("redis:// plaintext transport", message)
        self.assertIn("credentials and event data are unencrypted", message)
        self.assertNotIn("secret-value", message)
        self.assertNotIn("private-redis.internal", message)
        self.assertEqual(publisher.metrics()["configured"], 1)
        redis_module.Redis.from_url.assert_called_once_with(
            url,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
            health_check_interval=30,
        )

    def test_tls_transport_log_matches_required_certificate_validation(self) -> None:
        url = "rediss://vpn-dashboard:secret-value@private-redis.internal:6380/0"
        publisher = RedisStreamPublisher(url, client=_FakeRedis())

        with self.assertLogs("integrations", level=logging.INFO) as captured:
            tls_publisher = RedisStreamPublisher(url, client=_FakeRedis())

        message = "\n".join(captured.output)
        self.assertIn("rediss:// TLS transport", message)
        self.assertIn("certificate and hostname validation enabled", message)
        self.assertNotIn("secret-value", message)
        self.assertNotIn("private-redis.internal", message)
        self.assertEqual(publisher.metrics()["configured"], 1)
        self.assertEqual(tls_publisher.metrics()["configured"], 1)

    def test_acl_document_matches_client_command_surface_without_broad_category(self) -> None:
        documentation = (Path(__file__).parents[1] / "docs" / "REDIS_ROTATION.md").read_text(
            encoding="utf-8"
        )
        acl_lines = [
            line for line in documentation.splitlines() if line.startswith("user vpn-dashboard ")
        ]

        self.assertTrue(acl_lines)
        self.assertNotIn("+@connection", "\n".join(acl_lines))
        expected_commands = {
            "+hello",
            "+ping",
            "+xadd",
            "+get",
            "+set",
            "+incr",
            "+del",
            "+eval",
            "+pexpire",
            "+info",
        }
        self.assertGreaterEqual(len(acl_lines), 3)
        for line in acl_lines:
            self.assertIn("~vpn-dashboard.events", line)
            self.assertIn("~vpn-dashboard.review.*", line)
            grants = set(line.split())
            command_grants = {grant for grant in grants if grant.startswith("+")}
            self.assertIn(command_grants, [expected_commands, expected_commands | {"+client|setinfo"}])
        self.assertIn("redis-py==8.1.0", documentation)
        self.assertIn("default RESP3 handshake uses\n`HELLO`", documentation)
        self.assertIn("does not issue `SELECT`", documentation)
        self.assertIn("omit `+client|setinfo`", documentation)
        self.assertNotIn("+@connection +xadd", documentation)

    def test_documentation_preserves_plaintext_compatibility_and_surfaces_tls(self) -> None:
        documentation = (Path(__file__).parents[1] / "docs" / "REDIS_ROTATION.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("`redis://` remains supported", documentation)
        self.assertIn("isolated, trusted\nprivate container network", documentation)
        self.assertIn("`rediss://` enables TLS\ntransport", documentation)
        self.assertIn("explicitly requires certificate validation and\nhostname checking", documentation)


if __name__ == "__main__":
    unittest.main()
