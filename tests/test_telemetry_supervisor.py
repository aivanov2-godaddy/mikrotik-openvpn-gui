import threading
import unittest
from unittest.mock import patch

from routeros_binary import RouterOSReply
from telemetry_broker import TelemetryBroker
from telemetry_gateway import TelemetryGatewayContract, TelemetryPrincipal
from telemetry_supervisor import (
    INTERFACE_COUNTER_PROPLIST,
    TelemetryCredentialLease,
    TelemetryInterfaceSampler,
    TelemetrySupervisor,
    TelemetrySupervisorConfig,
    read_interface_counters,
)


class FakeConnection:
    def __init__(self, replies=(), error=None):
        self.replies = list(replies)
        self.error = error
        self.connected = False
        self.closed = False
        self.paths = []
        self.credentials = None

    def connect(self, username, password):
        self.credentials = (username, password)
        if self.error is not None:
            raise self.error
        self.connected = True

    def listen(self, path, *, query=()):
        self.paths.append((path, tuple(query)))
        yield from self.replies

    def execute(self, path, *, query=()):
        self.paths.append((path, tuple(query)))
        return self.replies

    def close(self):
        self.closed = True


class TelemetrySupervisorTests(unittest.TestCase):
    def test_interface_sampler_run_forever_paces_samples_start_to_start(self):
        class StopAfterWait:
            def __init__(self):
                self.stopped = False
                self.delays = []

            def is_set(self):
                return self.stopped

            def wait(self, delay):
                self.delays.append(delay)
                self.stopped = True
                return True

        stop_event = StopAfterWait()
        sampler = TelemetryInterfaceSampler(
            lambda: None,
            lambda: ("user", "secret"),
            TelemetryBroker(),
            interval=1.0,
            stop_event=stop_event,
        )
        with (
            patch.object(sampler, "sample_once"),
            patch("telemetry_supervisor.time.monotonic", side_effect=[100.0, 100.25]),
        ):
            sampler.run_forever(max_samples=1)

        self.assertEqual(len(stop_event.delays), 1)
        self.assertAlmostEqual(stop_event.delays[0], 0.75, places=6)

    def test_interface_reader_requests_only_allow_listed_counters(self):
        connection = FakeConnection([RouterOSReply("re", {".id": "*1", "name": "ether1", "comment": "private"})])
        records = read_interface_counters(connection)
        self.assertEqual(records[0]["name"], "ether1")
        self.assertEqual(connection.paths, [('/interface/print', (INTERFACE_COUNTER_PROPLIST,))])

    def test_interface_sampler_uses_separate_connection_and_publishes_rates(self):
        counters = iter(("10", "1010"))
        sample_times = iter((100.999, 102.001))
        connections = []

        def create_connection():
            connection = FakeConnection(
                [RouterOSReply("re", {".id": "*1", "name": "ether1", "rx-byte": next(counters)})]
            )
            connections.append(connection)
            return connection

        broker = TelemetryBroker(clock=lambda: 500, monotonic_clock=lambda: next(sample_times))
        received = []
        sampler = TelemetryInterfaceSampler(
            create_connection,
            lambda: ("user", "secret"),
            broker,
            on_events=received.extend,
        )
        first = sampler.sample_once()
        events = sampler.sample_once()

        self.assertEqual(first[0].name, "vpn.interface.counters")
        self.assertEqual(events[0].name, "vpn.interface.counters")
        self.assertEqual(received[0].payload["interface"]["name"], "ether1")
        self.assertAlmostEqual(events[0].payload["interface"]["rx_bytes_per_second"], 1000 / 1.002)
        self.assertEqual(events[0].router_timestamp, 500)
        self.assertTrue(all(connection.closed for connection in connections))

    def test_interface_sampler_counts_poll_cycles_not_interface_events(self):
        replies = [
            RouterOSReply("re", {".id": "*1", "name": "ether1", "rx-byte": "10"}),
            RouterOSReply("re", {".id": "*2", "name": "ether2", "rx-byte": "20"}),
        ]
        connection = FakeConnection(replies)
        broker = TelemetrySupervisor(
            lambda: connection,
            lambda: ("user", "secret"),
        ).broker
        samples = []
        events = []
        sampler = TelemetryInterfaceSampler(
            lambda: connection,
            lambda: ("user", "secret"),
            broker,
            on_sample=lambda: samples.append(True),
            on_events=events.extend,
        )

        sampler.sample_once()
        connection.closed = False
        sampler.sample_once()

        self.assertEqual(len(samples), 2)
        self.assertEqual(len(events), 4)
        self.assertTrue(all(event.name == "vpn.interface.counters" for event in events))

    def test_interface_sampler_does_not_mark_failed_observation_fresh(self):
        connection = FakeConnection(error=OSError("unavailable"))
        broker = TelemetrySupervisor(
            lambda: connection,
            lambda: ("user", "secret"),
        ).broker
        samples = []
        sampler = TelemetryInterfaceSampler(
            lambda: connection,
            lambda: ("user", "secret"),
            broker,
            on_sample=lambda: samples.append(True),
        )

        with self.assertRaises(OSError):
            sampler.sample_once()

        self.assertEqual(samples, [])

    def test_disabled_by_default_does_not_create_connection(self):
        created = []
        supervisor = TelemetrySupervisor(
            lambda: created.append(True),
            lambda: ("router-user", "router-password"),
        )

        supervisor.run_forever(max_attempts=1)

        self.assertEqual(created, [])
        self.assertEqual(supervisor.health().as_dict(), {
            "status": "disabled",
            "enabled": False,
            "attempts": 0,
            "reconnects": 0,
            "failures": 0,
            "events": 0,
            "last_connected_at": None,
            "last_event_at": None,
            "last_snapshot_at": None,
            "last_error_code": None,
            "backoff_seconds": 1.0,
            "broker_sequence": 0,
        })

    def test_read_only_listen_publishes_redacted_events_and_closes(self):
        connection = FakeConnection([
            RouterOSReply("re", {
                ".id": "*1",
                "name": "alice",
                "address": "10.8.0.2",
                "password": "must-not-leak",
            }),
        ])
        received = []
        supervisor = TelemetrySupervisor(
            lambda: connection,
            lambda: ("router-user", "router-password"),
            config=TelemetrySupervisorConfig(enabled=True),
            clock=lambda: 100,
            on_events=received.extend,
        )

        with self.assertRaisesRegex(Exception, "listen_ended"):
            supervisor.run_attempt()

        self.assertEqual(connection.credentials, ("router-user", "router-password"))
        self.assertEqual(connection.paths, [("/ppp/active", ())])
        self.assertTrue(connection.closed)
        self.assertEqual(received[0].name, "vpn.session.connected")
        self.assertNotIn("password", received[0].as_dict()["payload"])
        self.assertEqual(supervisor.health().status, "healthy")

    def test_revoked_source_session_blocks_event_publish_and_closes_connection(self):
        connection = FakeConnection([
            RouterOSReply("re", {".id": "*1", "name": "alice", "address": "10.8.0.2"}),
        ])
        received = []
        checks = iter((True, True, False))
        supervisor = TelemetrySupervisor(
            lambda: connection,
            lambda: ("router-user", "router-password"),
            config=TelemetrySupervisorConfig(enabled=True),
            on_events=received.extend,
            authorization_check=lambda _username, _password: next(checks),
        )

        with self.assertRaisesRegex(Exception, "credentials_unavailable"):
            supervisor.run_attempt()

        self.assertEqual(received, [])
        self.assertEqual(supervisor.health().events, 0)
        self.assertEqual(supervisor.broker.sequence, 0)
        self.assertEqual(supervisor.broker.snapshot(), [])
        self.assertTrue(connection.closed)

    def test_credential_lease_is_cleared_and_stream_checks_only_reference(self):
        connection = FakeConnection([
            RouterOSReply("re", {".id": "*1", "name": "alice", "address": "10.8.0.2"}),
        ])
        lease = TelemetryCredentialLease("router-user", "router-password", "session-ref")
        self.assertNotIn("router-password", repr(lease))
        self.assertNotIn("session-ref", repr(lease))
        checked_refs = []
        supervisor = TelemetrySupervisor(
            lambda: connection,
            lambda: lease,
            config=TelemetrySupervisorConfig(enabled=True),
            authorization_ref_check=lambda ref: checked_refs.append(ref) or True,
        )

        with self.assertRaisesRegex(Exception, "listen_ended"):
            supervisor.run_attempt()

        self.assertEqual(lease.password, "")
        self.assertTrue(checked_refs)
        self.assertEqual(set(checked_refs), {"session-ref"})

    def test_credential_lease_revocation_blocks_publish(self):
        connection = FakeConnection([
            RouterOSReply("re", {".id": "*1", "name": "alice", "address": "10.8.0.2"}),
        ])
        lease = TelemetryCredentialLease("router-user", "router-password", "session-ref")
        received = []
        checks = iter((True, True, False))
        supervisor = TelemetrySupervisor(
            lambda: connection,
            lambda: lease,
            config=TelemetrySupervisorConfig(enabled=True),
            on_events=received.extend,
            authorization_ref_check=lambda _ref: next(checks),
        )

        with self.assertRaisesRegex(Exception, "credentials_unavailable"):
            supervisor.run_attempt()

        self.assertEqual(lease.password, "")
        self.assertEqual(received, [])
        self.assertEqual(supervisor.health().events, 0)
        self.assertTrue(connection.closed)

    def test_credential_lease_fails_closed_when_atomic_dispatch_denies(self):
        connection = FakeConnection([
            RouterOSReply("re", {".id": "*1", "name": "alice", "address": "10.8.0.2"}),
        ])
        lease = TelemetryCredentialLease("router-user", "router-password", "session-ref")
        received = []
        supervisor = TelemetrySupervisor(
            lambda: connection,
            lambda: lease,
            config=TelemetrySupervisorConfig(enabled=True),
            on_events=received.extend,
            authorization_ref_check=lambda _ref: True,
            authorization_ref_dispatch=lambda _ref, _dispatch: False,
        )

        with self.assertRaisesRegex(Exception, "credentials_unavailable"):
            supervisor.run_attempt()

        self.assertEqual(received, [])
        self.assertEqual(supervisor.health().events, 0)
        self.assertTrue(connection.closed)

    def test_idle_stream_connection_closes_when_source_session_is_revoked(self):
        class BlockingConnection(FakeConnection):
            def __init__(self):
                super().__init__()
                self.listen_started = threading.Event()
                self.close_requested = threading.Event()

            def listen(self, path, *, query=()):
                self.paths.append((path, tuple(query)))
                self.listen_started.set()
                if self.close_requested.wait(2):
                    return
                yield RouterOSReply("re", {".id": "*1", "name": "must-not-publish"})

            def close(self):
                self.closed = True
                self.close_requested.set()

        connection = BlockingConnection()
        valid = {"value": True}
        lease = TelemetryCredentialLease("router-user", "router-password", "session-ref")
        received = []
        failures = []
        supervisor = TelemetrySupervisor(
            lambda: connection,
            lambda: lease,
            config=TelemetrySupervisorConfig(
                enabled=True, authorization_poll_interval=0.01
            ),
            on_events=received.extend,
            authorization_ref_check=lambda _ref: valid["value"],
        )

        def run_attempt():
            try:
                supervisor.run_attempt()
            except Exception as error:  # noqa: BLE001 - capture worker exit for assertion
                failures.append(error)

        worker = threading.Thread(target=run_attempt)
        worker.start()
        self.assertTrue(connection.listen_started.wait(1))
        valid["value"] = False
        worker.join(1)

        self.assertFalse(worker.is_alive())
        self.assertTrue(connection.closed)
        self.assertEqual(received, [])
        self.assertEqual(len(failures), 1)

    def test_authorization_poll_interval_must_be_positive(self):
        with self.assertRaisesRegex(ValueError, "authorization_poll_interval"):
            TelemetrySupervisorConfig(authorization_poll_interval=0)

    def test_revoked_source_session_blocks_snapshot_reconciliation_publish(self):
        connection = FakeConnection()
        received = []
        checks = iter((True, True, True, False))
        supervisor = TelemetrySupervisor(
            lambda: connection,
            lambda: ("router-user", "router-password"),
            snapshot_reader=lambda _connection: [{".id": "*1", "name": "alice"}],
            config=TelemetrySupervisorConfig(enabled=True),
            on_events=received.extend,
            authorization_check=lambda _username, _password: next(checks),
        )

        with self.assertRaisesRegex(Exception, "credentials_unavailable"):
            supervisor.run_attempt()

        self.assertEqual(received, [])
        self.assertEqual(supervisor.health().last_snapshot_at, None)
        self.assertEqual(supervisor.broker.sequence, 0)
        self.assertEqual(supervisor.broker.snapshot(), [])
        self.assertTrue(connection.closed)

    def test_atomic_snapshot_dispatch_denial_leaves_no_recoverable_broker_state(self):
        connection = FakeConnection()
        lease = TelemetryCredentialLease("router-user", "router-password", "session-ref")
        broker = TelemetryBroker()
        received = []
        supervisor = TelemetrySupervisor(
            lambda: connection,
            lambda: lease,
            broker=broker,
            snapshot_reader=lambda _connection: [{".id": "*1", "name": "alice"}],
            config=TelemetrySupervisorConfig(enabled=True),
            on_events=received.extend,
            authorization_ref_check=lambda _ref: True,
            authorization_ref_dispatch=lambda _ref, _dispatch: False,
        )

        with self.assertRaisesRegex(Exception, "credentials_unavailable"):
            supervisor.run_attempt()

        self.assertEqual(received, [])
        self.assertEqual(broker.sequence, 0)
        self.assertEqual(broker.snapshot(), [])
        self.assertTrue(connection.closed)

        event_connection = FakeConnection([
            RouterOSReply("re", {".id": "*2", "name": "bob", "address": "10.8.0.3"})
        ])
        event_supervisor = TelemetrySupervisor(
            lambda: event_connection,
            lambda: TelemetryCredentialLease("router-user", "router-password", "session-ref"),
            broker=broker,
            config=TelemetrySupervisorConfig(enabled=True),
            on_events=received.extend,
            authorization_ref_check=lambda _ref: True,
            authorization_ref_dispatch=lambda _ref, _dispatch: False,
        )
        with self.assertRaisesRegex(Exception, "credentials_unavailable"):
            event_supervisor.run_attempt()

        self.assertEqual(received, [])
        self.assertEqual(broker.sequence, 0)
        self.assertEqual(broker.snapshot(), [])
        self.assertTrue(event_connection.closed)

        gateway = TelemetryGatewayContract(broker)
        subscription = gateway.open(
            TelemetryPrincipal(True, auth_method="routeros", role="owner")
        )
        recovery = gateway.poll(subscription, after_sequence=-1)
        self.assertEqual(recovery[0]["payload"]["sessions"], [])

    def test_sampler_revocation_after_read_does_not_mark_sample_fresh_or_publish(self):
        connection = FakeConnection([RouterOSReply("re", {".id": "*1", "name": "ether1"})])
        received = []
        samples = []
        checks = iter((True, False))
        broker = TelemetryBroker()
        sampler = TelemetryInterfaceSampler(
            lambda: connection,
            lambda: ("router-user", "router-password"),
            broker,
            on_sample=lambda: samples.append(True),
            on_events=received.extend,
            authorization_check=lambda _username, _password: next(checks),
        )

        with self.assertRaisesRegex(Exception, "credentials_unavailable"):
            sampler.sample_once()

        self.assertEqual(samples, [])
        self.assertEqual(received, [])
        self.assertTrue(connection.closed)

    def test_sampler_atomic_dispatch_denial_does_not_reconcile_or_mark_fresh(self):
        connection = FakeConnection([
            RouterOSReply("re", {".id": "*1", "name": "ether1", "rx-byte": "10"})
        ])
        lease = TelemetryCredentialLease("router-user", "router-password", "session-ref")
        received = []
        samples = []
        broker = TelemetryBroker()
        sampler = TelemetryInterfaceSampler(
            lambda: connection,
            lambda: lease,
            broker,
            on_sample=lambda: samples.append(True),
            on_events=received.extend,
            authorization_ref_check=lambda _ref: True,
            authorization_ref_dispatch=lambda _ref, _dispatch: False,
        )

        with self.assertRaisesRegex(Exception, "credentials_unavailable"):
            sampler.sample_once()

        self.assertEqual(lease.password, "")
        self.assertEqual(broker.sequence, 0)
        self.assertEqual(samples, [])
        self.assertEqual(received, [])
        self.assertTrue(connection.closed)

    def test_snapshot_is_reconciled_before_stream(self):
        connection = FakeConnection([])
        received = []
        supervisor = TelemetrySupervisor(
            lambda: connection,
            lambda: ("user", "secret"),
            snapshot_reader=lambda _connection: [{
                ".id": "*snapshot",
                "name": "alice",
                "rx-byte": "12",
            }],
            config=TelemetrySupervisorConfig(enabled=True),
            clock=lambda: 200,
            on_events=received.extend,
        )

        with self.assertRaisesRegex(Exception, "listen_ended"):
            supervisor.run_attempt()

        self.assertEqual(received[-1].name, "telemetry.snapshot")
        self.assertEqual(supervisor.broker.snapshot()[0]["rx_bytes"], 12)
        self.assertEqual(supervisor.health().last_snapshot_at, 200)

    def test_transient_stream_failure_reconnects_snapshots_then_resumes_events(self):
        first = FakeConnection()

        def interrupted_listen(_path, *, query=()):
            yield RouterOSReply("re", {".id": "*1", "name": "alice", "address": "10.8.0.2"})
            raise OSError("stream interrupted")

        first.listen = interrupted_listen
        second = FakeConnection([
            RouterOSReply("re", {".id": "*3", "name": "carol", "address": "10.8.0.4"}),
        ])
        connections = iter([first, second])
        received = []
        supervisor = TelemetrySupervisor(
            lambda: next(connections),
            lambda: ("user", "secret"),
            snapshot_reader=lambda connection: [] if connection is first else [
                {".id": "*2", "name": "bob", "address": "10.8.0.3"},
            ],
            config=TelemetrySupervisorConfig(enabled=True, initial_backoff=0.001, max_backoff=0.001),
            on_events=received.extend,
        )

        supervisor.run_forever(max_attempts=2)

        names = [event.name for event in received]
        self.assertEqual(names, [
            "telemetry.snapshot",
            "vpn.session.connected",
            "vpn.session.disconnected",
            "vpn.session.connected",
            "telemetry.snapshot",
            "vpn.session.connected",
        ])
        snapshot = received[4].payload["sessions"]
        self.assertEqual([session["name"] for session in snapshot], ["bob"])
        self.assertEqual([session["name"] for session in supervisor.broker.snapshot()], ["bob", "carol"])
        sequences = [event.sequence for event in received]
        self.assertEqual(sequences, sorted(sequences))
        self.assertEqual(supervisor.health().reconnects, 1)
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)

    def test_failed_initial_connection_is_not_counted_as_reconnect(self):
        failed = FakeConnection(error=OSError("initial connection failed"))
        connected = FakeConnection()
        connections = iter([failed, connected])
        supervisor = TelemetrySupervisor(
            lambda: next(connections),
            lambda: ("user", "secret"),
            config=TelemetrySupervisorConfig(enabled=True, initial_backoff=0.001, max_backoff=0.001),
        )

        supervisor.run_forever(max_attempts=2)

        health = supervisor.health()
        self.assertEqual(health.attempts, 2)
        self.assertEqual(health.failures, 2)
        self.assertEqual(health.reconnects, 0)
        self.assertIsNotNone(health.last_connected_at)
        self.assertTrue(failed.closed)
        self.assertTrue(connected.closed)

    def test_snapshot_failures_keep_backoff_and_do_not_publish_partial_reconciliation(self):
        class RecordingStopEvent:
            def __init__(self):
                self.delays = []

            def is_set(self):
                return False

            def wait(self, delay):
                self.delays.append(delay)
                return False

        connections = [FakeConnection(), FakeConnection(), FakeConnection()]
        connection_iter = iter(connections)
        stop_event = RecordingStopEvent()
        received = []
        reads = 0

        def read_snapshot(_connection):
            nonlocal reads
            reads += 1
            if reads == 1:
                def interrupted_snapshot():
                    yield {".id": "*partial", "name": "partial"}
                    raise OSError("snapshot interrupted")

                return interrupted_snapshot()
            if reads == 2:
                self.assertEqual([item["name"] for item in supervisor.broker.snapshot()], ["alice"])
                self.assertEqual(received, [])
                self.assertEqual(supervisor.health().status, "connecting")
                raise OSError("snapshot unavailable")
            return [{".id": "*2", "name": "bob"}]

        supervisor = TelemetrySupervisor(
            lambda: next(connection_iter),
            lambda: ("user", "secret"),
            snapshot_reader=read_snapshot,
            config=TelemetrySupervisorConfig(enabled=True, initial_backoff=0.01, max_backoff=0.08),
            stop_event=stop_event,
            on_events=received.extend,
        )
        supervisor.broker.apply(RouterOSReply("re", {".id": "*1", "name": "alice"}), now=99)

        supervisor.run_forever(max_attempts=3)

        self.assertEqual(stop_event.delays, [0.01, 0.02, 0.01])
        self.assertEqual(reads, 3)
        self.assertEqual([item["name"] for item in supervisor.broker.snapshot()], ["bob"])
        self.assertTrue(any(event.name == "telemetry.snapshot" for event in received))
        self.assertFalse(any(event.payload.get("session", {}).get("name") == "partial" for event in received))
        self.assertEqual(sum(event.name == "telemetry.snapshot" for event in received), 1)
        self.assertTrue(all(connection.closed for connection in connections))

    def test_reconnect_backoff_is_bounded_and_error_is_redacted(self):
        created = []
        stop_event = threading.Event()

        def make_connection():
            created.append(True)
            return FakeConnection(error=OSError("password=secret router=10.0.0.1"))

        supervisor = TelemetrySupervisor(
            make_connection,
            lambda: ("user", "secret"),
            config=TelemetrySupervisorConfig(enabled=True, initial_backoff=0.001, max_backoff=0.002),
            stop_event=stop_event,
        )
        supervisor.run_forever(max_attempts=3)

        health = supervisor.health()
        self.assertEqual(len(created), 3)
        self.assertEqual(health.failures, 3)
        self.assertEqual(health.last_error_code, "connection_error")
        self.assertLessEqual(health.backoff_seconds, 0.002)
        self.assertNotIn("secret", str(health.as_dict()))

    def test_stop_interrupts_reconnect_loop(self):
        stop_event = threading.Event()
        calls = []

        def make_connection():
            calls.append(True)
            stop_event.set()
            return FakeConnection(error=OSError("unavailable"))

        supervisor = TelemetrySupervisor(
            make_connection,
            lambda: ("user", "secret"),
            config=TelemetrySupervisorConfig(enabled=True, initial_backoff=1, max_backoff=1),
            stop_event=stop_event,
        )
        supervisor.run_forever()

        self.assertEqual(len(calls), 1)
        self.assertEqual(supervisor.health().status, "stopped")


if __name__ == "__main__":
    unittest.main()
