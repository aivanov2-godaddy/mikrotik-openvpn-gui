import threading
import unittest

from routeros_binary import RouterOSReply
from telemetry_supervisor import (
    INTERFACE_COUNTER_PROPLIST,
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
    def test_interface_reader_requests_only_allow_listed_counters(self):
        connection = FakeConnection([RouterOSReply("re", {".id": "*1", "name": "ether1", "comment": "private"})])
        records = read_interface_counters(connection)
        self.assertEqual(records[0]["name"], "ether1")
        self.assertEqual(connection.paths, [('/interface/print', (INTERFACE_COUNTER_PROPLIST,))])

    def test_interface_sampler_uses_separate_connection_and_publishes_rates(self):
        connection = FakeConnection([RouterOSReply("re", {".id": "*1", "name": "ether1", "rx-byte": "10"})])
        broker = TelemetrySupervisor(
            lambda: connection,
            lambda: ("user", "secret"),
        ).broker
        received = []
        sampler = TelemetryInterfaceSampler(
            lambda: connection,
            lambda: ("user", "secret"),
            broker,
            clock=lambda: 100,
            on_events=received.extend,
        )
        events = sampler.sample_once()
        self.assertEqual(events[0].name, "vpn.interface.counters")
        self.assertEqual(received[0].payload["interface"]["name"], "ether1")
        self.assertTrue(connection.closed)

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
