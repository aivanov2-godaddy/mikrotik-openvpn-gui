"""Live Redis checks for cross-instance VPN-user review coordination."""

from __future__ import annotations

import os
import unittest
import uuid

from integrations import RedisReviewCoordinationError, RedisReviewCoordinator


@unittest.skipUnless(os.environ.get("REDIS_TEST_URL"), "REDIS_TEST_URL is not configured")
class RedisReviewCoordinationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        import redis

        url = os.environ["REDIS_TEST_URL"]
        self.first_client = redis.Redis.from_url(
            url, decode_responses=True, socket_connect_timeout=3, socket_timeout=3,
        )
        self.second_client = redis.Redis.from_url(
            url, decode_responses=True, socket_connect_timeout=3, socket_timeout=3,
        )
        self.first_client.ping()
        self.first = RedisReviewCoordinator(self.first_client, lock_wait_seconds=0.1)
        self.second = RedisReviewCoordinator(self.second_client, lock_wait_seconds=0.1)
        self.resource = f"vpn-user:redis-integration:{uuid.uuid4().hex}"

    def tearDown(self) -> None:
        for coordinator, client in (
            (getattr(self, "first", None), getattr(self, "first_client", None)),
            (getattr(self, "second", None), getattr(self, "second_client", None)),
        ):
            if coordinator is not None and client is not None:
                client.delete(
                    coordinator._revision_key(self.resource),
                    coordinator._lock_key(self.resource),
                )
                client.close()

    def test_revision_compare_lock_renewal_and_cross_instance_exclusion(self) -> None:
        epoch = self.first.current_epoch()
        self.assertEqual(self.second.current_epoch(), epoch)
        self.assertEqual(self.first.current_revision(self.resource), 0)

        with self.first.resource_lock(self.resource) as lock:
            lock.assert_owned()
            lock.renew()
            with self.assertRaises(RedisReviewCoordinationError):
                with self.second.resource_lock(self.resource):
                    self.fail("a second app instance acquired the active user lock")

        self.assertTrue(self.first.advance_if_current(self.resource, 0, epoch))
        self.assertEqual(self.second.current_revision(self.resource), 1)
        self.assertFalse(self.second.advance_if_current(self.resource, 0, epoch))


if __name__ == "__main__":
    unittest.main()
