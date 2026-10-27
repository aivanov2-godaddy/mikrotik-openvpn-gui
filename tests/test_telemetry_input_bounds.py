import unittest

from routeros_binary import (
    MAX_REPLY_FIELD_NAME_BYTES,
    MAX_REPLY_FIELD_VALUE_BYTES,
    RouterOSBinaryConnection,
    RouterOSBinaryError,
    RouterOSReply,
    decode_words,
    encode_sentence,
    parse_reply,
)
from telemetry_broker import (
    MAX_INTERFACE_SNAPSHOT_RECORDS,
    MAX_SESSION_SNAPSHOT_RECORDS,
    MAX_TELEMETRY_TEXT_BYTES,
    TelemetryBroker,
    TelemetryEvent,
    normalize_interface,
    normalize_session,
)
from telemetry_gateway import TelemetryGatewayContract, TelemetryGatewayError


class RouterOSBinaryInputBoundsTests(unittest.TestCase):
    def test_parse_reply_rejects_oversized_field_name_and_value(self) -> None:
        with self.assertRaisesRegex(RouterOSBinaryError, "field name"):
            parse_reply([b"!re", b"=" + b"k" * (MAX_REPLY_FIELD_NAME_BYTES + 1) + b"=v"])

        with self.assertRaisesRegex(RouterOSBinaryError, "field value"):
            parse_reply([b"!re", b"=name=" + b"x" * (MAX_REPLY_FIELD_VALUE_BYTES + 1)])

    def test_decode_words_rejects_a_word_over_the_global_limit(self) -> None:
        from routeros_binary import MAX_WORD_SIZE

        with self.assertRaisesRegex(RouterOSBinaryError, "word exceeds"):
            decode_words(encode_sentence([b"x" * (MAX_WORD_SIZE + 1)]))

    def test_execute_accepts_the_existing_path_specific_telemetry_proplist(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.sent = b""
                self.response = encode_sentence(["!done", ".tag=1"])

            def sendall(self, payload: bytes) -> None:
                self.sent += payload

            def recv(self, size: int) -> bytes:
                chunk, self.response = self.response[:size], self.response[size:]
                return chunk

            def close(self) -> None:
                return None

        fake = FakeSocket()
        connection = RouterOSBinaryConnection("router.example")
        connection._socket = fake  # noqa: SLF001 - inspect the bounded command sent to the fake transport

        connection.execute(
            "/ppp/active/print",
            query=(".proplist=.id,name,address,caller-id,uptime,encoding,service,rx-byte,tx-byte,rx-packet,tx-packet",),
        )

        words = decode_words(fake.sent)
        self.assertEqual(words[0], b"/ppp/active/print")
        self.assertEqual(
            words[1],
            b".proplist=.id,name,address,caller-id,uptime,encoding,service,rx-byte,tx-byte,rx-packet,tx-packet",
        )
        self.assertEqual(words[2], b".tag=1")

    def test_execute_rejects_expanded_or_non_allowlisted_query_words_before_send(self) -> None:
        class FakeSocket:
            sent = b""

            def sendall(self, payload: bytes) -> None:
                self.sent += payload

            def close(self) -> None:
                return None

        invalid_queries = (
            (".proplist=.id,name,password",),
            (".proplist=.id,address",),
            (".proplist=.id,name", ".tag=caller-controlled"),
            ("?name=alice",),
            (".proplist=.id,.id",),
            (".proplist=" + "x" * 1024,),
            ".proplist=.id,name",
            None,
            object(),
        )
        for query in invalid_queries:
            with self.subTest(query=query):
                fake = FakeSocket()
                connection = RouterOSBinaryConnection("router.example")
                connection._socket = fake  # noqa: SLF001 - verify validation precedes network I/O
                with self.assertRaisesRegex(ValueError, "path-specific allowlist"):
                    connection.execute("/interface/print", query=query)
                self.assertEqual(fake.sent, b"")

        def unbounded_query():
            while True:
                yield ".proplist=.id"

        fake = FakeSocket()
        connection = RouterOSBinaryConnection("router.example")
        connection._socket = fake  # noqa: SLF001 - verify bounded iteration of supplied query words
        with self.assertRaisesRegex(ValueError, "path-specific allowlist"):
            connection.execute("/interface/print", query=unbounded_query())
        self.assertEqual(fake.sent, b"")

    def test_listen_applies_the_same_path_specific_query_allowlist(self) -> None:
        class FakeSocket:
            sent = b""

            def sendall(self, payload: bytes) -> None:
                self.sent += payload

            def close(self) -> None:
                return None

        fake = FakeSocket()
        connection = RouterOSBinaryConnection("router.example")
        connection._socket = fake  # noqa: SLF001 - verify invalid listen queries are not sent
        with self.assertRaisesRegex(ValueError, "path-specific allowlist"):
            next(connection.listen("/ppp/active", query=(".proplist=.id,password",)))
        self.assertEqual(fake.sent, b"")


class TelemetryBrokerInputBoundsTests(unittest.TestCase):
    def test_normalizers_do_not_retain_oversized_routeros_text(self) -> None:
        self.assertIsNone(
            normalize_session({".id": "*1", "name": "u" * (MAX_TELEMETRY_TEXT_BYTES + 1)})
        )
        self.assertIsNone(normalize_session({".id": "*1", "name": "😀" * 65}))
        session = normalize_session(
            {".id": "*1", "name": "alice", "uptime": "x" * (MAX_TELEMETRY_TEXT_BYTES + 1)}
        )
        self.assertIsNotNone(session)
        assert session is not None
        self.assertEqual(session["uptime"], "")
        self.assertIsNone(
            normalize_interface({".id": "*if1", "name": "i" * (MAX_TELEMETRY_TEXT_BYTES + 1)})
        )
        counter = normalize_session(
            {".id": "*2", "name": "alice", "rx-byte": str(1 << 64), "tx-byte": "0"}
        )
        self.assertIsNotNone(counter)
        assert counter is not None
        self.assertEqual(counter["rx_bytes"], 0)
        self.assertFalse(counter["counter_complete"])

    def test_reconcile_rejects_excess_records_without_changing_cached_state(self) -> None:
        broker = TelemetryBroker()
        broker.apply(RouterOSReply("re", {".id": "*old", "name": "old"}))
        before = broker.snapshot()
        records = ({".id": f"*{index}", "name": "user"} for index in range(MAX_SESSION_SNAPSHOT_RECORDS + 1))

        with self.assertRaisesRegex(ValueError, "session snapshot exceeds"):
            broker.reconcile(records)

        self.assertEqual(broker.snapshot(), before)

    def test_interface_reconcile_rejects_excess_records(self) -> None:
        broker = TelemetryBroker()
        records = ({".id": f"*{index}", "name": "ether"} for index in range(MAX_INTERFACE_SNAPSHOT_RECORDS + 1))
        with self.assertRaisesRegex(ValueError, "interface snapshot exceeds"):
            broker.reconcile_interfaces(records)


class TelemetryGatewayInputBoundsTests(unittest.TestCase):
    @staticmethod
    def _session_event(broker: TelemetryBroker, index: int) -> TelemetryEvent:
        return broker.apply(
            RouterOSReply("re", {".id": f"*{index}", "name": f"user-{index}"})
        )[0]

    def test_gateway_rejects_oversized_fields_and_snapshot_collections(self) -> None:
        with self.assertRaisesRegex(TelemetryGatewayError, "text field exceeds"):
            TelemetryGatewayContract._frame(
                TelemetryEvent(
                    "vpn.session.connected",
                    1,
                    100,
                    {"id": "*1", "name": "x" * (MAX_TELEMETRY_TEXT_BYTES + 1)},
                )
            )

        with self.assertRaisesRegex(TelemetryGatewayError, "text field exceeds"):
            TelemetryGatewayContract._frame(
                TelemetryEvent("vpn.session.connected", 1, 100, {"id": "*1", "name": "😀" * 65})
            )

        with self.assertRaisesRegex(TelemetryGatewayError, "session limit"):
            TelemetryGatewayContract._frame(
                TelemetryEvent(
                    "telemetry.snapshot",
                    1,
                    100,
                    {"sessions": [{}] * (MAX_SESSION_SNAPSHOT_RECORDS + 1)},
                )
            )

    def test_replay_queue_evicts_frames_to_stay_under_aggregate_byte_budget(self) -> None:
        broker = TelemetryBroker()
        first = self._session_event(broker, 1)
        second = self._session_event(broker, 2)
        frame_size = TelemetryGatewayContract._build_frame(first)[1]
        gateway = TelemetryGatewayContract(
            broker,
            max_replay=10,
            max_frame_bytes=frame_size,
            max_replay_bytes=(frame_size * 2) - 1,
        )

        self.assertEqual(gateway.publish([first, second]), 2)
        metrics = gateway.metrics()
        self.assertEqual(metrics["buffered_events"], 1)
        self.assertEqual(metrics["buffered_frame_bytes"], frame_size)
        self.assertLessEqual(metrics["buffered_frame_bytes"], metrics["buffered_frame_bytes_limit"])

    def test_frame_over_instance_limit_is_rejected_without_retention(self) -> None:
        broker = TelemetryBroker()
        event = self._session_event(broker, 1)
        gateway = TelemetryGatewayContract(broker, max_frame_bytes=64, max_replay_bytes=256)

        with self.assertRaisesRegex(TelemetryGatewayError, "byte limit"):
            gateway.publish([event])

        self.assertEqual(gateway.metrics()["buffered_events"], 0)
        self.assertEqual(gateway.metrics()["buffered_frame_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
