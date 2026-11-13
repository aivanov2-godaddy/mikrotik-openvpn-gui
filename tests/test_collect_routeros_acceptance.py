from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from urllib.parse import urlsplit, parse_qs
from unittest.mock import Mock, patch

from routeros_binary import RouterOSBinaryConnection, RouterOSReply, decode_words, encode_sentence
from scripts.collect_routeros_acceptance import (
    CONTAINER_NAMES,
    HEALTHCHECK_CONTAINER_PROPLIST,
    LAYER_PROPLIST,
    LEGACY_CONTAINER_PROPLIST,
    MODERN_CONTAINER_PROPLIST,
    PARITY_TOLERANCE,
    RUNTIME_IDENTITY_CONTAINER_PROPLIST,
    RouterOSRestAcceptanceReader,
    _container_proplist_for_version,
    _snapshot,
    collect,
    main,
)

CANARY_DIGEST = "sha256:" + "d" * 64
PRODUCTION_REGISTRY_DIGEST = "sha256:" + "c" * 64
CANARY_CONFIG_DIGEST = "sha256:" + "1" * 64
PRODUCTION_CONFIG_DIGEST = "sha256:" + "4" * 64
CANARY_LAYERS = ["2" * 64, "3" * 64]
PRODUCTION_LAYERS = ["5" * 64, "6" * 64]


class RouterOSRuntimeIdentityTransportContractTests(unittest.TestCase):
    def test_runtime_identity_collector_queries_fit_binary_client_allowlist(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.sent = b""

            def sendall(self, payload: bytes) -> None:
                self.sent += payload

            def recv(self, _size: int) -> bytes:
                return encode_sentence(["!done", ".tag=1"])

            def close(self) -> None:
                return None

        queries = (
            ("/container/print", f".proplist={RUNTIME_IDENTITY_CONTAINER_PROPLIST}"),
            ("/container/layers/print", f".proplist={LAYER_PROPLIST}"),
        )
        for path, query in queries:
            with self.subTest(path=path):
                connection = RouterOSBinaryConnection("router.example")
                fake = FakeSocket()
                connection._socket = fake  # noqa: SLF001 - assert collector/client contract
                connection.execute(path, query=(query,))
                self.assertEqual(
                    decode_words(fake.sent),
                    [path.encode(), query.encode(), b".tag=1"],
                )


class RouterOSAcceptanceSamplerTests(unittest.TestCase):
    def _fake_connection(
        self,
        *,
        version="7.25.1 (stable)",
        lifecycle=None,
        active_sessions=1,
        session_sequence=None,
        canary_digest=CANARY_DIGEST,
        production_digest=None,
        healthcheck_status=None,
    ):
        connection = Mock()
        revision = "a" * 40
        try:
            container_proplist = _container_proplist_for_version(version)
            modern = container_proplist != LEGACY_CONTAINER_PROPLIST
            supports_healthcheck_status = container_proplist in {
                HEALTHCHECK_CONTAINER_PROPLIST,
                RUNTIME_IDENTITY_CONTAINER_PROPLIST,
            }
        except ValueError:
            modern = True
            supports_healthcheck_status = False
        state = lifecycle if lifecycle is not None else (
            {"running": "true", "healthy": "true"} if modern else {"status": "running"}
        )
        session_samples = session_sequence or [active_sessions]
        session_index = 0

        def image(environment):
            digest = canary_digest if environment == "canary" else production_digest
            return f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64" + (f"@{digest}" if digest else "")

        def execute(path, *, query=()):
            nonlocal session_index
            query = tuple(query)
            if path == "/system/resource/print":
                self.assertEqual(query, (".proplist=cpu-load,total-memory,free-memory,total-hdd-space,free-hdd-space,uptime,version",))
                return [
                    RouterOSReply("re", {"cpu-load": "23", "total-memory": "1000", "free-memory": "600", "total-hdd-space": "10000", "free-hdd-space": "7000", "uptime": "1d", "version": version}),
                    RouterOSReply("done", {}),
                ]
            if path == "/container/print":
                self.assertEqual(query, (f".proplist={container_proplist}",))
                records = []
                for environment, name in CONTAINER_NAMES.items():
                    record = {
                        "name": name,
                        **state,
                        "remote-image": image(environment),
                        "root-dir": "/must-not-leak",
                        "image-id": (
                            CANARY_CONFIG_DIGEST.removeprefix("sha256:")
                            if environment == "canary"
                            else PRODUCTION_CONFIG_DIGEST.removeprefix("sha256:")
                        ),
                        "layers": ",".join(
                            (CANARY_LAYERS if environment == "canary" else PRODUCTION_LAYERS)
                            + [f"{environment}-root"]
                        ),
                    }
                    if supports_healthcheck_status and healthcheck_status is not None:
                        record["healthcheck-status"] = healthcheck_status
                    records.append(RouterOSReply("re", record))
                return records + [RouterOSReply("done", {})]
            if path == "/container/layers/print":
                self.assertEqual(query, (".proplist=name,type,containers",))
                return [
                    RouterOSReply("re", {"name": digest, "type": "layer", "containers": f"{CONTAINER_NAMES[environment]}"})
                    for environment, digests in (("canary", CANARY_LAYERS), ("production", PRODUCTION_LAYERS))
                    for digest in digests
                ] + [
                    RouterOSReply("re", {"name": f"{environment}-root", "type": "root-dir", "containers": CONTAINER_NAMES[environment]})
                    for environment in CONTAINER_NAMES
                ] + [RouterOSReply("done", {})]
            if path == "/ppp/active/print":
                self.assertEqual(query, (".proplist=.id",))
                session_count = session_samples[min(session_index, len(session_samples) - 1)]
                session_index += 1
                return [
                    *[
                        RouterOSReply("re", {".id": f"*{index + 1}", "name": "private-user", "address": "10.0.0.2"})
                        for index in range(session_count)
                    ],
                    RouterOSReply("done", {}),
                ]
            self.fail(f"unexpected RouterOS path: {path}")

        connection.execute.side_effect = execute
        return connection

    def _fake_rest_reader(
        self,
        *,
        mismatch=False,
        active_sessions=1,
        session_sequence=None,
        canary_digest=CANARY_DIGEST,
        production_digest=None,
        healthcheck_status_categories=None,
    ):
        reader = Mock()
        revision = "a" * 40
        if healthcheck_status_categories is None:
            healthcheck_status_categories = ["unavailable"]
        snapshot = {
            "router_cpu_percent": 23 if not mismatch else 99,
            "router_memory_used_percent": 40.0,
            "router_storage_used_percent": 30.0,
            "active_vpn_sessions": active_sessions,
            "containers": {
                name: {
                    "healthy": True,
                    "revision": revision,
                    "configured_digest": canary_digest if name == "canary" else production_digest,
                    "runtime_manifest_digest": (
                        (canary_digest if name == "canary" else production_digest or PRODUCTION_REGISTRY_DIGEST)
                        if (name != "canary" or canary_digest == CANARY_DIGEST)
                        else None
                    ),
                    "runtime_manifest_digest_verified": name != "canary" or canary_digest == CANARY_DIGEST,
                    "registry_image_config_healthcheck_profile": (
                        "exec_wget_local_readyz_v1"
                        if name != "canary" or canary_digest == CANARY_DIGEST
                        else None
                    ),
                }
                for name in CONTAINER_NAMES
            },
            "healthcheck_status_categories": {
                name: list(healthcheck_status_categories)
                for name in CONTAINER_NAMES
            },
        }
        if session_sequence:
            session_index = 0

            def next_snapshot(**_kwargs):
                nonlocal session_index
                session_count = session_sequence[min(session_index, len(session_sequence) - 1)]
                session_index += 1
                return {**snapshot, "active_vpn_sessions": session_count}

            reader.snapshot.side_effect = next_snapshot
        else:
            reader.snapshot.return_value = snapshot
        return reader

    def _fake_registry_identity(self, image, *, timeout):
        self.assertEqual(timeout, 8)
        if "@" in image:
            manifest_digest = image.split("@", 1)[1]
            is_canary = manifest_digest == CANARY_DIGEST
        else:
            manifest_digest = PRODUCTION_REGISTRY_DIGEST
            is_canary = False
        return {
            "manifest_digest": manifest_digest,
            "config_digest": CANARY_CONFIG_DIGEST if is_canary else PRODUCTION_CONFIG_DIGEST,
            "layer_digests": [f"sha256:{item}" for item in (CANARY_LAYERS if is_canary else PRODUCTION_LAYERS)],
            "os": "linux",
            "architecture": "arm64",
            "image_healthcheck_profile": "exec_wget_local_readyz_v1",
        }

    def setUp(self):
        identity_patch = patch(
            "scripts.collect_routeros_acceptance.resolve_image_identity",
            side_effect=self._fake_registry_identity,
        )
        identity_patch.start()
        self.addCleanup(identity_patch.stop)

    def test_snapshot_only_returns_allowlisted_aggregate_values(self):
        report = _snapshot(self._fake_connection())
        self.assertEqual(report["router_cpu_percent"], 23)
        self.assertEqual(report["router_memory_used_percent"], 40.0)
        self.assertEqual(report["router_storage_used_percent"], 30.0)
        self.assertEqual(report["active_vpn_sessions"], 1)
        self.assertEqual(
            report["healthcheck_status_categories"]["canary"], ["unavailable"]
        )
        self.assertFalse(report["containers"]["canary"]["runtime_manifest_digest_verified"])
        self.assertIsNone(report["containers"]["canary"]["runtime_manifest_digest"])
        self.assertIsNone(
            report["containers"]["canary"]["registry_image_config_healthcheck_profile"]
        )
        self.assertNotIn("private-user", repr(report))
        self.assertNotIn("/must-not-leak", repr(report))

    def test_routeros_725_selects_runtime_identity_properties(self):
        self.assertEqual(
            _container_proplist_for_version("7.25.1 (stable)"),
            RUNTIME_IDENTITY_CONTAINER_PROPLIST,
        )

    def test_healthcheck_status_is_reduced_to_allowlisted_categories(self):
        raw_status = (
            "failed, output: resource temporarily unavailable; could not fork; "
            "segmentation fault"
        )
        report = _snapshot(self._fake_connection(healthcheck_status=raw_status))
        self.assertEqual(
            report["healthcheck_status_categories"]["canary"],
            ["failed", "resource_unavailable", "segmentation_fault"],
        )
        self.assertFalse(report["containers"]["canary"]["healthy"])
        self.assertNotIn(raw_status, repr(report))
        self.assertNotIn("could not fork", repr(report))

        good = _snapshot(
            self._fake_connection(healthcheck_status="good, output: no errors")
        )
        self.assertEqual(
            good["healthcheck_status_categories"]["canary"], ["good"]
        )
        self.assertTrue(good["containers"]["canary"]["healthy"])

        timeout = _snapshot(
            self._fake_connection(healthcheck_status="failed, output: timed out")
        )
        self.assertEqual(
            timeout["healthcheck_status_categories"]["canary"],
            ["failed", "timeout"],
        )
        self.assertFalse(timeout["containers"]["canary"]["healthy"])

        oversized_status = "failed, output: " + ("x" * 4096)
        oversized = _snapshot(
            self._fake_connection(healthcheck_status=oversized_status)
        )
        self.assertEqual(
            oversized["healthcheck_status_categories"]["canary"],
            ["unclassified"],
        )
        self.assertFalse(oversized["containers"]["canary"]["healthy"])
        self.assertNotIn(oversized_status, repr(oversized))

    def test_legacy_container_reply_reports_healthcheck_status_unavailable(self):
        report = _snapshot(self._fake_connection(version="7.19.10 (stable)"))
        self.assertEqual(
            report["healthcheck_status_categories"]["canary"],
            ["unavailable"],
        )

    def test_routeros_722_uses_lifecycle_fields_without_healthcheck_status(self):
        version = "7.22.1 (stable)"
        self.assertEqual(
            _container_proplist_for_version(version), MODERN_CONTAINER_PROPLIST
        )
        report = _snapshot(
            self._fake_connection(
                version=version,
                healthcheck_status="failed, output: timed out",
            )
        )
        self.assertTrue(all(item["healthy"] for item in report["containers"].values()))
        self.assertTrue(
            all(
                categories == ["unavailable"]
                for categories in report["healthcheck_status_categories"].values()
            )
        )

    def test_routeros_723_requests_healthcheck_status_as_diagnostic(self):
        version = "7.23.0 (stable)"
        self.assertEqual(
            _container_proplist_for_version(version), HEALTHCHECK_CONTAINER_PROPLIST
        )
        report = _snapshot(
            self._fake_connection(
                version=version,
                healthcheck_status="failed, output: timed out",
            )
        )
        self.assertTrue(all(not item["healthy"] for item in report["containers"].values()))
        self.assertTrue(
            all(
                categories == ["failed", "timeout"]
                for categories in report["healthcheck_status_categories"].values()
            )
        )

    def test_legacy_routeros_uses_status_property(self):
        report = _snapshot(self._fake_connection(version="7.19.10 (stable)"))
        self.assertTrue(all(item["healthy"] for item in report["containers"].values()))

    def test_unknown_routeros_version_fails_closed_before_container_query(self):
        connection = self._fake_connection(version="unknown")
        with self.assertRaises(ValueError):
            _snapshot(connection)
        self.assertEqual(
            [call.args[0] for call in connection.execute.call_args_list],
            ["/system/resource/print"],
        )

    def test_modern_unhealthy_or_missing_lifecycle_state_fails_closed(self):
        for lifecycle in (
            {"running": "true", "healthy": "false"},
            {"running": "true", "stopped": "true"},
            {},
        ):
            with self.subTest(lifecycle=lifecycle):
                report = _snapshot(self._fake_connection(lifecycle=lifecycle))
                self.assertTrue(all(not item["healthy"] for item in report["containers"].values()))

    def test_collector_closes_connection_and_redacts_raw_router_data(self):
        raw_healthcheck_status = "good, output: sensitive-healthcheck-detail"
        connection = self._fake_connection(healthcheck_status=raw_healthcheck_status)
        rest_reader = self._fake_rest_reader(healthcheck_status_categories=["failed"])
        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]
        report = collect(
            connection,
            rest_reader=rest_reader,
            username="reader",
            password="do-not-log",
            expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
            expected_digests={"canary": CANARY_DIGEST, "production": None},
            duration_seconds=1800,
            interval_seconds=60,
            clock=lambda: now + timedelta(seconds=elapsed[0]),
            monotonic=lambda: elapsed[0],
            sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
        )
        self.assertTrue(report["passed"])
        self.assertTrue(report["credentials_or_raw_router_data_written"] is False)
        self.assertNotIn("reader", repr(report))
        self.assertNotIn("do-not-log", repr(report))
        self.assertNotIn(raw_healthcheck_status, repr(report))
        self.assertNotIn("sensitive-healthcheck-detail", repr(report))
        self.assertNotIn("private-user", repr(report))
        self.assertTrue(all(item["healthy_for_all_successful_samples"] for item in report["containers"].values()))
        self.assertTrue(all(item["runtime_manifest_digest_verified"] for item in report["containers"].values()))
        self.assertEqual(report["containers"]["canary"]["runtime_manifest_digest"], CANARY_DIGEST)
        self.assertEqual(
            report["containers"]["canary"]["registry_image_config_healthcheck_profile"],
            "exec_wget_local_readyz_v1",
        )
        self.assertNotIn(CANARY_CONFIG_DIGEST.removeprefix("sha256:"), repr(report))
        self.assertNotIn(CANARY_LAYERS[0], repr(report))
        self.assertEqual(
            report["healthcheck_status_categories"],
            {"canary": ["good"], "production": ["good"]},
        )
        self.assertEqual(report["failed_gates"], [])
        connection.close.assert_called_once_with()
        rest_reader.close.assert_called_once_with()
        self.assertEqual(report["rest_parity_successful_sample_count"], report["sample_count"])
        self.assertEqual(report["rest_parity_failed_sample_count"], 0)

    def test_rest_binary_mismatch_fails_acceptance_without_payload_data(self):
        connection = self._fake_connection()
        rest_reader = self._fake_rest_reader(mismatch=True)
        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]
        report = collect(
            connection,
            rest_reader=rest_reader,
            username="reader",
            password="do-not-log",
            expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
            expected_digests={"canary": CANARY_DIGEST, "production": None},
            duration_seconds=1800,
            interval_seconds=60,
            clock=lambda: now + timedelta(seconds=elapsed[0]),
            monotonic=lambda: elapsed[0],
            sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
        )
        self.assertFalse(report["passed"])
        self.assertIn("routeros_rest_parity_unavailable_or_mismatched", report["failed_gates"])
        self.assertEqual(report["rest_parity_failed_sample_count"], report["sample_count"])
        self.assertNotIn("99", repr(report))
        self.assertNotIn("private-user", repr(report))

    def test_soak_requires_a_vpn_session_to_be_observed_at_least_once(self):
        connection = self._fake_connection(active_sessions=0)
        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]

        report = collect(
            connection,
            rest_reader=self._fake_rest_reader(active_sessions=0),
            username="reader",
            password="do-not-log",
            expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
            expected_digests={"canary": CANARY_DIGEST, "production": None},
            duration_seconds=1800,
            interval_seconds=60,
            clock=lambda: now + timedelta(seconds=elapsed[0]),
            monotonic=lambda: elapsed[0],
            sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
        )

        self.assertFalse(report["passed"])
        self.assertIn("vpn_test_session_not_observed", report["failed_gates"])
        self.assertEqual(report["active_vpn_sessions_max"], 0)

    def test_soak_allows_controlled_disconnect_after_observing_a_vpn_session(self):
        session_counts = [1] * 31
        session_counts[15] = 0
        connection = self._fake_connection(session_sequence=session_counts)
        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]

        report = collect(
            connection,
            rest_reader=self._fake_rest_reader(session_sequence=session_counts),
            username="reader",
            password="do-not-log",
            expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
            expected_digests={"canary": CANARY_DIGEST, "production": None},
            duration_seconds=1800,
            interval_seconds=60,
            clock=lambda: now + timedelta(seconds=elapsed[0]),
            monotonic=lambda: elapsed[0],
            sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
        )

        self.assertTrue(report["passed"], report["failed_gates"])
        self.assertEqual(report["active_vpn_sessions_min"], 0)
        self.assertEqual(report["active_vpn_sessions_max"], 1)

    def test_mutable_production_tag_change_during_routeros_soak_fails_closed(self):
        calls = {}
        changed_digest = "sha256:" + "e" * 64

        def resolver(image, *, timeout):
            identity = self._fake_registry_identity(image, timeout=timeout)
            if "@" not in image:
                calls[image] = calls.get(image, 0) + 1
                if calls[image] > 1:
                    return {**identity, "manifest_digest": changed_digest}
            return identity

        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        elapsed = [0.0]
        report = collect(
            self._fake_connection(),
            rest_reader=self._fake_rest_reader(),
            username="reader",
            password="do-not-log",
            expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
            expected_digests={"canary": CANARY_DIGEST, "production": None},
            duration_seconds=1800,
            interval_seconds=60,
            clock=lambda: now + timedelta(seconds=elapsed[0]),
            monotonic=lambda: elapsed[0],
            sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
            registry_identity_resolver=resolver,
        )

        self.assertFalse(report["passed"])
        self.assertIn("container_runtime_manifest_digest_unverified", report["failed_gates"])
        self.assertFalse(report["containers"]["production"]["runtime_manifest_digest_verified"])
        self.assertIsNone(report["containers"]["production"]["runtime_manifest_digest"])

    def test_unknown_or_unowned_runtime_layer_fails_closed(self):
        revision = "a" * 40
        references = {
            "canary": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64@{CANARY_DIGEST}",
            "production": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64",
        }
        identities = {name: self._fake_registry_identity(image, timeout=8) for name, image in references.items()}
        connection = self._fake_connection()
        original_execute = connection.execute.side_effect

        def with_unknown_layer(path, **kwargs):
            replies = original_execute(path, **kwargs)
            if path == "/container/layers/print":
                return replies[:-1] + [
                    RouterOSReply(
                        "re",
                        {"name": "unexpected-layer", "type": "opaque", "containers": CONTAINER_NAMES["canary"]},
                    ),
                    replies[-1],
                ]
            return replies

        connection.execute.side_effect = with_unknown_layer
        snapshot = _snapshot(
            connection,
            runtime_identities=identities,
            expected_image_references=references,
        )
        self.assertFalse(snapshot["containers"]["canary"]["runtime_manifest_digest_verified"])
        self.assertIsNone(snapshot["containers"]["canary"]["runtime_manifest_digest"])
        self.assertIsNone(
            snapshot["containers"]["canary"]["registry_image_config_healthcheck_profile"]
        )

    def test_untrusted_registry_profile_is_suppressed_even_for_verified_runtime(self):
        revision = "a" * 40
        references = {
            "canary": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64@{CANARY_DIGEST}",
            "production": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64",
        }
        identities = {
            name: self._fake_registry_identity(image, timeout=8)
            for name, image in references.items()
        }
        identities["canary"]["image_healthcheck_profile"] = ["untrusted"]

        snapshot = _snapshot(
            self._fake_connection(),
            runtime_identities=identities,
            expected_image_references=references,
        )

        self.assertTrue(snapshot["containers"]["canary"]["runtime_manifest_digest_verified"])
        self.assertIsNone(
            snapshot["containers"]["canary"]["registry_image_config_healthcheck_profile"]
        )

    def test_configured_digest_is_bound_throughout_window_and_rest_parity(self):
        alternate = "sha256:" + "e" * 64

        def sample(connection, rest_reader, production_digest=None):
            now = datetime(2026, 10, 10, tzinfo=timezone.utc)
            elapsed = [0.0]
            return collect(
                connection,
                rest_reader=rest_reader,
                username="reader",
                password="do-not-log",
                expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
                expected_digests={"canary": CANARY_DIGEST, "production": production_digest},
                duration_seconds=1800,
                interval_seconds=60,
                clock=lambda: now + timedelta(seconds=elapsed[0]),
                monotonic=lambda: elapsed[0],
                sleep=lambda delay: elapsed.__setitem__(0, elapsed[0] + delay),
            )

        changed_canary = sample(
            self._fake_connection(canary_digest=alternate),
            self._fake_rest_reader(canary_digest=alternate),
        )
        self.assertIn("container_configured_digest_mismatch", changed_canary["failed_gates"])
        self.assertEqual(changed_canary["rest_parity_failed_sample_count"], 0)

        parity_mismatch = sample(
            self._fake_connection(),
            self._fake_rest_reader(canary_digest=alternate),
        )
        self.assertIn("routeros_rest_parity_unavailable_or_mismatched", parity_mismatch["failed_gates"])

        pinned_production = sample(
            self._fake_connection(production_digest=alternate),
            self._fake_rest_reader(production_digest=alternate),
            production_digest=alternate,
        )
        self.assertTrue(pinned_production["passed"], pinned_production["failed_gates"])
        self.assertEqual(pinned_production["containers"]["production"]["observed_configured_digests"], [alternate])

        tag_only_production = sample(
            self._fake_connection(),
            self._fake_rest_reader(),
            production_digest=alternate,
        )
        self.assertIn("container_configured_digest_mismatch", tag_only_production["failed_gates"])

    def test_rest_reader_rejects_non_https_and_embedded_credentials(self):
        for url in ("http://router.example", "https://reader:secret@router.example", "https://router.example/rest?x=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                RouterOSRestAcceptanceReader(url, "reader", "secret")

    def test_rest_reader_uses_only_bounded_allowlisted_gets(self):
        reader = RouterOSRestAcceptanceReader("https://router.example/rest", "reader", "secret")
        opener = Mock()
        payloads = {
            "/rest/system/resource": [{
                "cpu-load": "23", "total-memory": "1000", "free-memory": "600",
                "total-hdd-space": "10000", "free-hdd-space": "7000", "uptime": "1d",
                "version": "7.24.5 (stable)",
            }],
            "/rest/container": [
                {
                    "name": name,
                    "running": "true",
                    "healthy": "true",
                    "healthcheck-status": "good, output: ",
                    "remote-image": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'a' * 40}-arm64",
                }
                for name in CONTAINER_NAMES.values()
            ],
            "/rest/ppp/active": [{".id": "*1", "name": "private-user", "address": "10.0.0.2"}],
        }

        def open_request(request, *, timeout):
            self.assertEqual(timeout, 10)
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.get_header("Accept"), "application/json")
            self.assertEqual(request.get_header("Authorization"), "Basic cmVhZGVyOnNlY3JldA==")
            parsed = urlsplit(request.full_url)
            self.assertEqual(parsed.scheme, "https")
            query = parse_qs(parsed.query)
            self.assertEqual(len(query), 1)
            if parsed.path == "/rest/container":
                version = payloads["/rest/system/resource"][0]["version"]
                expected_container_proplist = {
                    "7.19.10 (stable)": LEGACY_CONTAINER_PROPLIST,
                    "7.22.1 (stable)": MODERN_CONTAINER_PROPLIST,
                    "7.23.0 (stable)": HEALTHCHECK_CONTAINER_PROPLIST,
                    "7.24.5 (stable)": HEALTHCHECK_CONTAINER_PROPLIST,
                }.get(version)
                self.assertIsNotNone(expected_container_proplist)
                expected_proplist = expected_container_proplist
            else:
                expected_proplist = {
                    "/rest/system/resource": "cpu-load,total-memory,free-memory,total-hdd-space,free-hdd-space,uptime,version",
                    "/rest/ppp/active": ".id",
                }[parsed.path]
            self.assertEqual(query, {".proplist": [expected_proplist]})
            self.assertIn(parsed.path, payloads)
            response = Mock()
            response.status = 200
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read.return_value = json.dumps(payloads[parsed.path]).encode()
            return response

        opener.open.side_effect = open_request
        reader._opener = opener
        snapshot = reader.snapshot()
        self.assertEqual(snapshot["active_vpn_sessions"], 1)
        self.assertTrue(all(item["healthy"] for item in snapshot["containers"].values()))
        self.assertTrue(
            all(
                categories == ["good"]
                for categories in snapshot["healthcheck_status_categories"].values()
            )
        )
        self.assertNotIn("private-user", repr(snapshot))
        self.assertEqual(opener.open.call_count, 3)

        payloads["/rest/system/resource"][0]["version"] = "7.22.1 (stable)"
        payloads["/rest/container"] = [
            {
                "name": name,
                "running": "true",
                "healthy": "true",
                "remote-image": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'a' * 40}-arm64",
            }
            for name in CONTAINER_NAMES.values()
        ]
        modern_snapshot = reader.snapshot()
        self.assertTrue(all(item["healthy"] for item in modern_snapshot["containers"].values()))
        self.assertTrue(
            all(
                categories == ["unavailable"]
                for categories in modern_snapshot["healthcheck_status_categories"].values()
            )
        )
        self.assertEqual(opener.open.call_count, 6)

        payloads["/rest/system/resource"][0]["version"] = "7.23.0 (stable)"
        payloads["/rest/container"] = [
            {
                "name": name,
                "running": "true",
                "healthy": "true",
                "healthcheck-status": "failed, output: sensitive-timeout-detail",
                "remote-image": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'a' * 40}-arm64",
            }
            for name in CONTAINER_NAMES.values()
        ]
        healthcheck_snapshot = reader.snapshot()
        self.assertTrue(all(not item["healthy"] for item in healthcheck_snapshot["containers"].values()))
        self.assertTrue(
            all(
                categories == ["failed", "timeout"]
                for categories in healthcheck_snapshot["healthcheck_status_categories"].values()
            )
        )
        self.assertNotIn("sensitive-timeout-detail", repr(healthcheck_snapshot))
        self.assertEqual(opener.open.call_count, 9)

        payloads["/rest/system/resource"][0]["version"] = "7.19.10 (stable)"
        payloads["/rest/container"] = [
            {"name": name, "status": "running", "remote-image": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{'a' * 40}-arm64"}
            for name in CONTAINER_NAMES.values()
        ]
        legacy_snapshot = reader.snapshot()
        self.assertTrue(all(item["healthy"] for item in legacy_snapshot["containers"].values()))
        self.assertTrue(
            all(
                categories == ["unavailable"]
                for categories in legacy_snapshot["healthcheck_status_categories"].values()
            )
        )
        self.assertEqual(opener.open.call_count, 12)

        payloads["/rest/system/resource"][0]["version"] = "unknown"
        with self.assertRaises(ValueError):
            reader.snapshot()
        self.assertEqual(opener.open.call_count, 13)
        reader.close()
        self.assertEqual(reader._authorization, "")

    def test_rest_runtime_identity_uses_typed_layer_rows_and_keeps_ids_private(self):
        reader = RouterOSRestAcceptanceReader("https://router.example/rest", "reader", "secret")
        revision = "a" * 40
        identities = {
            "canary": {
                "manifest_digest": CANARY_DIGEST,
                "config_digest": CANARY_CONFIG_DIGEST,
                "layer_digests": [f"sha256:{value}" for value in CANARY_LAYERS],
                "os": "linux",
                "architecture": "arm64",
                "image_healthcheck_profile": "exec_wget_local_readyz_v1",
            },
            "production": {
                "manifest_digest": PRODUCTION_REGISTRY_DIGEST,
                "config_digest": PRODUCTION_CONFIG_DIGEST,
                "layer_digests": [f"sha256:{value}" for value in PRODUCTION_LAYERS],
                "os": "linux",
                "architecture": "arm64",
                "image_healthcheck_profile": "shell_timeout_wget_local_readyz_v1",
            },
        }
        references = {
            "canary": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64@{CANARY_DIGEST}",
            "production": f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{revision}-arm64",
        }
        payloads = {
            "/rest/system/resource": [{
                "cpu-load": "23", "total-memory": "1000", "free-memory": "600",
                "total-hdd-space": "10000", "free-hdd-space": "7000", "uptime": "1d",
                "version": "7.25.1 (stable)",
            }],
            "/rest/container": [
                {
                    "name": CONTAINER_NAMES[environment],
                    "running": "true",
                    "healthy": "true",
                    "healthcheck-status": "good, output: ",
                    "remote-image": references[environment],
                    "image-id": identities[environment]["config_digest"].removeprefix("sha256:"),
                    "layers": (CANARY_LAYERS if environment == "canary" else PRODUCTION_LAYERS)
                    + [f"{environment}-root"],
                }
                for environment in CONTAINER_NAMES
            ],
            "/rest/container/layers": [
                *[
                    {
                        "name": digest,
                        "type": "layer",
                        "containers": [CONTAINER_NAMES[environment]],
                    }
                    for environment, digests in (("canary", CANARY_LAYERS), ("production", PRODUCTION_LAYERS))
                    for digest in digests
                ],
                *[
                    {
                        "name": f"{environment}-root",
                        "type": "root-dir",
                        "containers": [CONTAINER_NAMES[environment]],
                    }
                    for environment in CONTAINER_NAMES
                ],
            ],
            "/rest/ppp/active": [{".id": "*1", "name": "private-user", "address": "10.0.0.2"}],
        }
        opener = Mock()

        def open_request(request, *, timeout):
            path = urlsplit(request.full_url).path
            expected_proplists = {
                "/rest/system/resource": "cpu-load,total-memory,free-memory,total-hdd-space,free-hdd-space,uptime,version",
                "/rest/container": RUNTIME_IDENTITY_CONTAINER_PROPLIST,
                "/rest/container/layers": "name,type,containers",
                "/rest/ppp/active": ".id",
            }
            self.assertEqual(parse_qs(urlsplit(request.full_url).query), {".proplist": [expected_proplists[path]]})
            response = Mock()
            response.status = 200
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read.return_value = json.dumps(payloads[path]).encode()
            return response

        opener.open.side_effect = open_request
        reader._opener = opener
        snapshot = reader.snapshot(
            runtime_identities=identities,
            expected_image_references=references,
        )

        self.assertEqual(opener.open.call_count, 4)
        self.assertTrue(all(
            item["runtime_manifest_digest_verified"]
            for item in snapshot["containers"].values()
        ))
        self.assertEqual(
            snapshot["containers"]["canary"]["runtime_manifest_digest"],
            CANARY_DIGEST,
        )
        self.assertEqual(
            snapshot["containers"]["canary"]["registry_image_config_healthcheck_profile"],
            "exec_wget_local_readyz_v1",
        )
        self.assertEqual(
            snapshot["containers"]["production"]["registry_image_config_healthcheck_profile"],
            "shell_timeout_wget_local_readyz_v1",
        )
        self.assertNotIn(CANARY_CONFIG_DIGEST.removeprefix("sha256:"), repr(snapshot))
        self.assertNotIn(CANARY_LAYERS[0], repr(snapshot))
        self.assertNotIn("private-user", repr(snapshot))
        reader.close()

    def test_parity_tolerances_are_small_and_explicit(self):
        self.assertEqual(PARITY_TOLERANCE["router_cpu_percent"], 10.0)
        self.assertEqual(PARITY_TOLERANCE["router_memory_used_percent"], 1.0)
        self.assertEqual(PARITY_TOLERANCE["router_storage_used_percent"], 1.0)

    def test_bad_window_is_rejected(self):
        connection = self._fake_connection()
        with self.assertRaises(ValueError):
            collect(
                connection,
                rest_reader=self._fake_rest_reader(),
                username="reader",
                password="secret",
                expected_revisions={name: "a" * 40 for name in CONTAINER_NAMES},
                expected_digests={"canary": CANARY_DIGEST, "production": None},
                duration_seconds=60,
            )
        connection.connect.assert_not_called()

    def test_missing_expected_container_fails_closed(self):
        connection = self._fake_connection()
        connection.execute.side_effect = lambda path, **kwargs: (
            [RouterOSReply("re", {"cpu-load": "1", "total-memory": "100", "free-memory": "50", "total-hdd-space": "100", "free-hdd-space": "50"}), RouterOSReply("done", {})]
            if path == "/system/resource/print"
            else [RouterOSReply("done", {})]
        )
        with self.assertRaises(ValueError):
            _snapshot(connection)

    def test_cli_failure_replaces_stale_pass_report_with_redacted_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "acceptance.json"
            output.write_text('{"passed": true, "failed_gates": []}\n', encoding="utf-8")
            argv = [
                "collect_routeros_acceptance.py",
                "--output",
                str(output),
                "--canary-revision",
                "a" * 40,
                "--canary-digest",
                CANARY_DIGEST,
                "--production-revision",
                "b" * 40,
            ]
            environment = {
                "ROUTEROS_ACCEPTANCE_HOST": "router-secret.invalid",
                "ROUTEROS_ACCEPTANCE_USERNAME": "acceptance-reader",
                "ROUTEROS_ACCEPTANCE_PASSWORD": "password-must-not-leak",
                "ROUTEROS_ACCEPTANCE_REST_URL": "https://router-secret.invalid",
                "ROUTEROS_ACCEPTANCE_REST_USERNAME": "acceptance-reader",
                "ROUTEROS_ACCEPTANCE_REST_PASSWORD": "password-must-not-leak",
            }
            stdout = io.StringIO()
            with (
                patch.object(sys, "argv", argv),
                patch.dict(os.environ, environment, clear=True),
                patch("scripts.collect_routeros_acceptance.RouterOSBinaryConnection", side_effect=OSError("router-secret.invalid password-must-not-leak")),
                redirect_stdout(stdout),
            ):
                exit_code = main()

            report_text = output.read_text(encoding="utf-8")
            report = json.loads(report_text)
            self.assertEqual(exit_code, 2)
            self.assertFalse(report["collected"])
            self.assertFalse(report["passed"])
            self.assertEqual(report["failed_gates"], ["collection_failed"])
            self.assertEqual(report["error"], "OSError")
            self.assertFalse(report["credentials_or_raw_router_data_written"])
            self.assertNotIn("router-secret.invalid", report_text)
            self.assertNotIn("password-must-not-leak", report_text)
            self.assertNotIn("router-secret.invalid", stdout.getvalue())
            self.assertNotIn("password-must-not-leak", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
