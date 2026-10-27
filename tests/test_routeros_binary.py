import ssl
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from routeros import RouterOSError
from routeros_binary import (
    RouterOSBinaryError,
    RouterOSBinaryConnection,
    SentenceReader,
    decode_length,
    decode_words,
    encode_length,
    encode_sentence,
    parse_reply,
)


class RouterOSBinaryCodecTests(unittest.TestCase):
    def test_length_boundaries_round_trip(self) -> None:
        for length in (0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0x0FFFFFFF, 0x10000000):
            encoded = encode_length(length)
            decoded, offset = decode_length(encoded)
            self.assertEqual(decoded, length)
            self.assertEqual(offset, len(encoded))

    def test_sentence_and_reply_records(self) -> None:
        encoded = encode_sentence(["/ppp/active/listen", ".tag=7"])
        self.assertEqual(
            decode_words(encoded),
            [b"/ppp/active/listen", b".tag=7"],
        )
        reply = parse_reply([b"!re", b"=.id=*1", b"=name=alice", b"=service=ovpn"])
        self.assertEqual(reply.kind, "re")
        self.assertEqual(reply.attributes[".id"], "*1")
        self.assertEqual(reply.attributes["name"], "alice")
        self.assertFalse(reply.dead)

    def test_dead_record_is_explicit(self) -> None:
        reply = parse_reply([b"!re", b"=.id=*1", b"=.dead=yes"])
        self.assertTrue(reply.dead)

    def test_incremental_reader_handles_split_words_and_sentences(self) -> None:
        payload = encode_sentence(["!re", "=.id=*1", "=name=alice"]) + encode_sentence(["!done"])
        reader = SentenceReader()
        results = []
        for byte in payload:
            results.extend(reader.feed(bytes((byte,))))
        self.assertEqual(results, [[b"!re", b"=.id=*1", b"=name=alice"], [b"!done"]])

    def test_reader_rejects_oversized_word(self) -> None:
        reader = SentenceReader(max_word_size=4)
        with self.assertRaises(RouterOSBinaryError):
            list(reader.feed(encode_sentence([b"!re", b"12345"])))

    def test_reader_rejects_sentence_with_too_many_words(self) -> None:
        reader = SentenceReader(max_words=3)
        with self.assertRaisesRegex(RouterOSBinaryError, "word limit"):
            list(reader.feed(encode_sentence([b"!re", b"=a=1", b"=b=2", b"=c=3"])))

    def test_parse_reply_rejects_too_many_words_without_copying_all_input(self) -> None:
        def words():
            yield b"!re"
            for _ in range(4_097):
                yield b"=name=value"

        with self.assertRaisesRegex(RouterOSBinaryError, "word limit"):
            parse_reply(words())

    def test_connection_rejects_oversized_response_with_sanitized_routeros_error(self) -> None:
        private_payload = b"PRIVATE_SENTINEL_" + b"x" * 80

        class FakeSocket:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload
                self.received = 0

            def recv(self, size: int) -> bytes:
                chunk = self.payload[:size]
                self.payload = self.payload[size:]
                self.received += len(chunk)
                return chunk

            def sendall(self, _payload: bytes) -> None:
                return None

            def close(self) -> None:
                return None

        connection = RouterOSBinaryConnection("router.example")
        fake = FakeSocket(encode_sentence([b"!re", b".tag=1", b"=detail=" + private_payload]))
        connection._socket = fake  # noqa: SLF001 - exercise bounded response handling

        with mock.patch("routeros_binary.MAX_RESPONSE_BYTES", 32):
            with self.assertRaises(RouterOSError) as raised:
                connection.execute("/interface/print")

        self.assertIn("configured safety limit", str(raised.exception))
        self.assertEqual(raised.exception.failure_kind, "invalid_response")
        self.assertNotIn("PRIVATE_SENTINEL", str(raised.exception))
        self.assertLessEqual(fake.received, 32)
        self.assertLessEqual(len(connection._reader._buffer), 32)  # noqa: SLF001
        self.assertIsNone(connection._socket)  # noqa: SLF001 - limit failures poison the socket

    def test_connection_rejects_reply_count_over_limit_before_accumulating_more(self) -> None:
        class FakeSocket:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload
                self.recv_calls = 0

            def recv(self, size: int) -> bytes:
                self.recv_calls += 1
                chunk = self.payload[:size]
                self.payload = self.payload[size:]
                return chunk

            def sendall(self, _payload: bytes) -> None:
                return None

            def close(self) -> None:
                return None

        payload = encode_sentence(["!re", ".tag=1", "=name=ether1"]) + encode_sentence(["!done", ".tag=1"])
        connection = RouterOSBinaryConnection("router.example")
        fake = FakeSocket(payload)
        connection._socket = fake  # noqa: SLF001 - exercise reply count ceiling

        with mock.patch("routeros_binary.MAX_RESPONSE_REPLIES", 1):
            with self.assertRaisesRegex(RouterOSBinaryError, "configured reply limit"):
                connection.execute("/interface/print")

        self.assertEqual(fake.recv_calls, 1)

    def test_connection_rejects_aggregate_response_over_byte_limit(self) -> None:
        class FakeSocket:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload
                self.received = 0

            def recv(self, size: int) -> bytes:
                chunk = self.payload[:size]
                self.payload = self.payload[size:]
                self.received += len(chunk)
                return chunk

            def sendall(self, _payload: bytes) -> None:
                return None

            def close(self) -> None:
                return None

        payload = encode_sentence(["!re", ".tag=1"]) + encode_sentence(["!done", ".tag=1"])
        connection = RouterOSBinaryConnection("router.example")
        fake = FakeSocket(payload)
        connection._socket = fake  # noqa: SLF001 - exercise aggregate response ceiling

        with mock.patch("routeros_binary.MAX_RESPONSE_BYTES", 15):
            with self.assertRaisesRegex(RouterOSError, "configured safety limit"):
                connection.execute("/interface/print")

        self.assertLessEqual(fake.received, 15)

    def test_connection_rejects_aggregate_word_limit_before_accumulating_replies(self) -> None:
        class FakeSocket:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload
                self.closed = False

            def recv(self, size: int) -> bytes:
                chunk = self.payload[:size]
                self.payload = self.payload[size:]
                return chunk

            def sendall(self, _payload: bytes) -> None:
                return None

            def close(self) -> None:
                self.closed = True

        payload = encode_sentence(["!re", ".tag=1", "=name=ether1"]) + encode_sentence(["!done", ".tag=1"])
        connection = RouterOSBinaryConnection("router.example")
        fake = FakeSocket(payload)
        connection._socket = fake  # noqa: SLF001 - exercise aggregate decoded-word ceiling

        with mock.patch("routeros_binary.MAX_RESPONSE_WORDS", 4):
            with self.assertRaisesRegex(RouterOSBinaryError, "configured word limit"):
                connection.execute("/interface/print")

        self.assertTrue(fake.closed)
        self.assertIsNone(connection._socket)  # noqa: SLF001 - word-limit failures poison the socket

    def test_connection_accepts_normal_response_within_bounded_limits(self) -> None:
        class FakeSocket:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload
                self.recv_calls = 0

            def recv(self, size: int) -> bytes:
                self.recv_calls += 1
                chunk = self.payload[:size]
                self.payload = self.payload[size:]
                return chunk

            def sendall(self, _payload: bytes) -> None:
                return None

            def close(self) -> None:
                return None

        payload = encode_sentence(["!re", ".tag=1", "=.id=*1", "=name=ether1"]) + encode_sentence(["!done", ".tag=1"])
        connection = RouterOSBinaryConnection("router.example")
        fake = FakeSocket(payload)
        connection._socket = fake  # noqa: SLF001 - exercise bounded normal response

        with (
            mock.patch("routeros_binary.MAX_RESPONSE_BYTES", 128),
            mock.patch("routeros_binary.MAX_RESPONSE_REPLIES", 2),
        ):
            replies = connection.execute("/interface/print")

        self.assertEqual([reply.kind for reply in replies], ["re", "done"])
        self.assertEqual(replies[0].attributes["name"], "ether1")
        self.assertEqual(fake.recv_calls, 1)

    def test_request_closes_connection_on_mismatched_reply_tag(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.closed = False

            def sendall(self, _payload: bytes) -> None:
                return None

            def recv(self, _size: int) -> bytes:
                return encode_sentence(["!done", ".tag=other"])

            def close(self) -> None:
                self.closed = True

        connection = RouterOSBinaryConnection("router.example")
        fake = FakeSocket()
        connection._socket = fake  # noqa: SLF001 - exercise response-tag validation
        with self.assertRaisesRegex(RouterOSBinaryError, "tag did not match"):
            connection.execute("/interface/print")
        self.assertTrue(fake.closed)
        self.assertIsNone(connection._socket)  # noqa: SLF001

    def test_connection_preserves_multiple_sentences_in_one_read(self) -> None:
        class FakeSocket:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload
                self.recv_calls = 0

            def recv(self, _size: int) -> bytes:
                self.recv_calls += 1
                if self.recv_calls == 1:
                    return self.payload
                return b""

            def close(self) -> None:
                return None

        connection = RouterOSBinaryConnection("router.example")
        fake = FakeSocket(encode_sentence(["!re", "=.id=*1"]) + encode_sentence(["!done"]))
        connection._socket = fake  # noqa: SLF001 - exercise buffered reader behavior
        self.assertEqual(connection._read_sentence(), [b"!re", b"=.id=*1"])  # noqa: SLF001
        self.assertEqual(connection._read_sentence(), [b"!done"])  # noqa: SLF001
        self.assertEqual(fake.recv_calls, 1)

    def test_concurrent_close_does_not_race_reader_state(self) -> None:
        class BlockingSocket:
            def __init__(self) -> None:
                self.recv_started = threading.Event()
                self.closed = threading.Event()

            def recv(self, _size: int) -> bytes:
                self.recv_started.set()
                self.closed.wait(1)
                return encode_sentence(["!re", "=.id=*1"])

            def close(self) -> None:
                self.closed.set()

        connection = RouterOSBinaryConnection("router.example")
        fake = BlockingSocket()
        connection._socket = fake  # noqa: SLF001 - exercise close/read concurrency
        failures = []

        def read() -> None:
            try:
                connection._read_sentence()  # noqa: SLF001 - exercise close/read concurrency
            except Exception as error:  # noqa: BLE001 - inspect concurrent close failure
                failures.append(error)

        worker = threading.Thread(target=read)
        worker.start()
        self.assertTrue(fake.recv_started.wait(1))
        connection.close()
        worker.join(1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], RouterOSBinaryError)
        self.assertEqual(connection._socket, None)  # noqa: SLF001

    def test_execute_is_read_only_and_returns_records(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.sent = b""

            def sendall(self, payload: bytes) -> None:
                self.sent += payload

            def recv(self, _size: int) -> bytes:
                return encode_sentence(["!re", ".tag=1", "=.id=*1", "=name=ether1"]) + encode_sentence(["!done", ".tag=1"])

            def close(self) -> None:
                return None

        connection = RouterOSBinaryConnection("router.example")
        fake = FakeSocket()
        connection._socket = fake  # noqa: SLF001 - exercise the read-only command boundary
        replies = connection.execute("/interface/print", query=(".proplist=.id,name",))
        self.assertEqual(replies[0].attributes["name"], "ether1")
        self.assertIn(b"/interface/print", fake.sent)
        self.assertNotIn(b"/interface/add", fake.sent)

    def test_insecure_tls_cannot_be_enabled(self) -> None:
        with self.assertRaisesRegex(RouterOSBinaryError, "certificate verification cannot be disabled"):
            RouterOSBinaryConnection("router.example", insecure_tls=True)

    def test_connection_uses_verified_tls_with_tls12_minimum(self) -> None:
        connection = RouterOSBinaryConnection("router.example")
        raw_socket = mock.Mock()
        wrapped_socket = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = wrapped_socket
        done = SimpleNamespace(kind="done", attributes={})

        with (
            mock.patch("routeros_binary.socket.create_connection", return_value=raw_socket),
            mock.patch("routeros_binary.ssl.create_default_context", return_value=context) as create_context,
            mock.patch.object(connection, "_request", return_value=[done]),
        ):
            connection.connect("admin", "password")

        create_context.assert_called_once_with(cafile=None)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="router.example")
        connection.close()

    def test_legacy_routeros_challenge_fails_closed_without_downgrade(self) -> None:
        connection = RouterOSBinaryConnection("router.example")
        raw_socket = mock.Mock()
        wrapped_socket = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = wrapped_socket
        challenge = SimpleNamespace(kind="done", attributes={"ret": "00112233445566778899aabbccddeeff"})

        with (
            mock.patch("routeros_binary.socket.create_connection", return_value=raw_socket),
            mock.patch("routeros_binary.ssl.create_default_context", return_value=context),
            mock.patch.object(connection, "_request", return_value=[challenge]) as request,
        ):
            with self.assertRaisesRegex(RouterOSBinaryError, "unsupported legacy login challenge"):
                connection.connect("admin", "password")

        request.assert_called_once()
        wrapped_socket.close.assert_called_once()
        self.assertIsNone(connection._socket)  # noqa: SLF001 - verify fail-closed cleanup


if __name__ == "__main__":
    unittest.main()
