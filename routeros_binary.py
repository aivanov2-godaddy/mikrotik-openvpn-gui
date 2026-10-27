"""Small RouterOS Binary API transport primitives.

The live-telemetry migration starts with a read-only protocol layer.  This
module deliberately does not expose RouterOS credentials to callers outside
the dashboard process and does not contain any configuration-mutating
helpers.  The production telemetry broker will build on these primitives in a
later, separately reviewable change.
"""

from __future__ import annotations

import socket
import ssl
import threading
from dataclasses import dataclass
from typing import Iterable, Iterator

from routeros import RouterOSError


MAX_WORD_SIZE = 1 << 20
MAX_SENTENCE_SIZE = 4 << 20
MAX_RESPONSE_BYTES = 16 << 20
MAX_RESPONSE_REPLIES = 10_000
MAX_REPLY_WORDS = 4_096
MAX_RESPONSE_WORDS = 65_536


class RouterOSBinaryError(RouterOSError):
    """Raised when the Binary API stream is malformed or rejected."""


def encode_length(length: int) -> bytes:
    """Encode one RouterOS API word length."""
    if length < 0:
        raise ValueError("word length cannot be negative")
    if length < 0x80:
        return bytes((length,))
    if length < 0x4000:
        return bytes(((length >> 8) | 0x80, length & 0xFF))
    if length < 0x200000:
        return bytes(((length >> 16) | 0xC0, (length >> 8) & 0xFF, length & 0xFF))
    if length < 0x10000000:
        return bytes(
            (
                (length >> 24) | 0xE0,
                (length >> 16) & 0xFF,
                (length >> 8) & 0xFF,
                length & 0xFF,
            )
        )
    if length >= 0x100000000:
        raise ValueError("word length exceeds the RouterOS API limit")
    return b"\xF0" + length.to_bytes(4, "big")


def decode_length(data: bytes | bytearray | memoryview, offset: int = 0) -> tuple[int, int]:
    """Decode one RouterOS API word length and return ``(length, next)``."""
    if offset >= len(data):
        raise RouterOSBinaryError("truncated RouterOS API length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    if first < 0xC0:
        if offset >= len(data):
            raise RouterOSBinaryError("truncated two-byte RouterOS API length")
        return ((first & 0x3F) << 8) | data[offset], offset + 1
    if first < 0xE0:
        if offset + 1 >= len(data):
            raise RouterOSBinaryError("truncated three-byte RouterOS API length")
        return (
            ((first & 0x1F) << 16) | (data[offset] << 8) | data[offset + 1],
            offset + 2,
        )
    if first < 0xF0:
        if offset + 2 >= len(data):
            raise RouterOSBinaryError("truncated four-byte RouterOS API length")
        return (
            ((first & 0x0F) << 24)
            | (data[offset] << 16)
            | (data[offset + 1] << 8)
            | data[offset + 2],
            offset + 3,
        )
    if first == 0xF0:
        if offset + 4 > len(data):
            raise RouterOSBinaryError("truncated five-byte RouterOS API length")
        return int.from_bytes(data[offset : offset + 4], "big"), offset + 4
    raise RouterOSBinaryError("reserved RouterOS API length prefix")


def encode_word(word: str | bytes) -> bytes:
    payload = word.encode("utf-8") if isinstance(word, str) else bytes(word)
    return encode_length(len(payload)) + payload


def encode_sentence(words: Iterable[str | bytes]) -> bytes:
    """Encode a complete sentence, including its zero-length terminator."""
    return b"".join(encode_word(word) for word in words) + b"\x00"


def decode_words(data: bytes) -> list[bytes]:
    """Decode a complete sentence without its sentence terminator."""
    words: list[bytes] = []
    offset = 0
    while offset < len(data):
        length, offset = decode_length(data, offset)
        if length == 0:
            if offset != len(data):
                raise RouterOSBinaryError("data follows RouterOS API sentence terminator")
            return words
        end = offset + length
        if end > len(data):
            raise RouterOSBinaryError("truncated RouterOS API word")
        words.append(data[offset:end])
        offset = end
    raise RouterOSBinaryError("missing RouterOS API sentence terminator")


@dataclass(frozen=True, slots=True)
class RouterOSReply:
    kind: str
    attributes: dict[str, str]

    @property
    def dead(self) -> bool:
        return self.attributes.get(".dead", "").casefold() == "yes"


def parse_reply(words: Iterable[bytes]) -> RouterOSReply:
    iterator = iter(words)
    first = next(iterator, None)
    if first is None or not first.startswith(b"!"):
        raise RouterOSBinaryError("RouterOS reply does not have a reply kind")
    kind = first.decode("utf-8", "replace")[1:]
    attributes: dict[str, str] = {}
    for word_count, raw in enumerate(iterator, start=2):
        if word_count > MAX_REPLY_WORDS:
            raise RouterOSBinaryError(
                "RouterOS Binary API reply exceeds configured word limit",
                failure_kind="invalid_response",
            )
        text = raw.decode("utf-8", "replace")
        if text.startswith("="):
            key, separator, value = text[1:].partition("=")
        elif text.startswith("."):
            key, separator, value = text.partition("=")
        else:
            key, separator, value = text.partition("=")
        if separator:
            attributes[key] = value
        else:
            attributes[text] = ""
        if len(attributes) > MAX_REPLY_WORDS - 1:
            raise RouterOSBinaryError(
                "RouterOS Binary API reply exceeds configured attribute limit",
                failure_kind="invalid_response",
            )
    return RouterOSReply(kind, attributes)


class SentenceReader:
    """Incrementally decode API sentences from a TCP byte stream."""

    def __init__(
        self,
        *,
        max_word_size: int = MAX_WORD_SIZE,
        max_sentence_size: int = MAX_SENTENCE_SIZE,
        max_words: int = MAX_REPLY_WORDS,
    ) -> None:
        if max_word_size < 1 or max_sentence_size < 1 or max_words < 1:
            raise ValueError("RouterOS API reader limits must be positive")
        self._buffer = bytearray()
        self.max_word_size = max_word_size
        self.max_sentence_size = max_sentence_size
        self.max_words = max_words
        self._scan_offset = 0
        self._words: list[bytes] = []

    def _complete_sentence(self, limit: int) -> tuple[list[bytes], int] | None:
        offset = self._scan_offset
        while True:
            try:
                length, next_offset = decode_length(self._buffer, offset)
            except RouterOSBinaryError as error:
                if str(error).startswith("truncated"):
                    return None
                raise
            if next_offset > limit:
                raise RouterOSBinaryError(
                    "RouterOS Binary API response exceeds configured safety limit",
                    failure_kind="invalid_response",
                )
            if length == 0:
                words = self._words
                self._words = []
                self._scan_offset = 0
                return words, next_offset
            if length > self.max_word_size:
                raise RouterOSBinaryError("RouterOS API word exceeds configured safety limit")
            if len(self._words) >= self.max_words:
                raise RouterOSBinaryError(
                    "RouterOS Binary API sentence exceeds configured word limit",
                    failure_kind="invalid_response",
                )
            end = next_offset + length
            if end > limit:
                raise RouterOSBinaryError(
                    "RouterOS Binary API response exceeds configured safety limit",
                    failure_kind="invalid_response",
                )
            if end > len(self._buffer):
                return
            self._words.append(bytes(self._buffer[next_offset:end]))
            offset = end
            self._scan_offset = offset

    def feed(
        self,
        data: bytes,
        *,
        max_sentence_size: int | None = None,
        max_sentences: int | None = None,
    ) -> Iterator[list[bytes]]:
        """Incrementally decode sentences without buffering past the byte limit."""
        limit = self.max_sentence_size
        if max_sentence_size is not None:
            limit = min(limit, max_sentence_size)
        if limit < 1:
            raise RouterOSBinaryError(
                "RouterOS Binary API response exceeds configured safety limit",
                failure_kind="invalid_response",
            )

        view = memoryview(data)
        cursor = 0
        emitted = 0
        while True:
            complete = self._complete_sentence(limit)
            if complete is not None:
                words, sentence_size = complete
                del self._buffer[:sentence_size]
                yield words
                emitted += 1
                if max_sentences is not None and emitted >= max_sentences:
                    remaining = view[cursor:]
                    if len(self._buffer) + len(remaining) > limit:
                        raise RouterOSBinaryError(
                            "RouterOS Binary API response exceeds configured safety limit",
                            failure_kind="invalid_response",
                        )
                    self._buffer.extend(remaining)
                    return
                continue
            if len(self._buffer) >= limit:
                raise RouterOSBinaryError(
                    "RouterOS Binary API response exceeds configured safety limit",
                    failure_kind="invalid_response",
                )
            if cursor >= len(view):
                return
            take = min(limit - len(self._buffer), len(view) - cursor)
            self._buffer.extend(view[cursor : cursor + take])
            cursor += take


def _sentence_wire_size(words: Iterable[bytes]) -> int:
    """Return a sentence's encoded size without constructing a second payload."""
    return 1 + sum(len(word) + len(encode_length(len(word))) for word in words)


class RouterOSBinaryConnection:
    """Minimal read-only connection used by the future telemetry broker.

    The connection intentionally exposes only sentence execution and a
    caller-controlled ``listen`` generator.  No write/configuration helpers
    belong here; profile issuance and RouterOS mutations remain on the
    existing REST client until a separate review approves otherwise.
    """

    def __init__(
        self,
        host: str,
        *,
        port: int = 8729,
        ca_file: str | None = None,
        timeout: float = 10.0,
        insecure_tls: bool = False,
    ) -> None:
        if insecure_tls:
            raise RouterOSBinaryError("TLS certificate verification cannot be disabled for RouterOS Binary API")
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ca_file = ca_file
        self._socket: socket.socket | ssl.SSLSocket | None = None
        self._state_lock = threading.RLock()
        self._tag = 0
        self._reader = SentenceReader()

    def connect(self, username: str, password: str) -> None:
        if self._socket is not None:
            return
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        context = ssl.create_default_context(cafile=self.ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        wrapped = context.wrap_socket(raw, server_hostname=self.host)
        wrapped.settimeout(self.timeout)
        self._socket = wrapped
        replies = self._request(["/login", f"=name={username}", f"=password={password}"])
        # The legacy challenge response is an MD5-based RouterOS v6 protocol.
        # This application targets RouterOS 7 and fails closed rather than
        # downgrading authentication when a legacy router responds.
        challenge = next(
            (reply.attributes.get("ret") for reply in replies if reply.kind == "done"),
            None,
        )
        if challenge:
            self.close()
            raise RouterOSBinaryError(
                "RouterOS returned an unsupported legacy login challenge; RouterOS 7 authentication is required"
            )

    def close(self) -> None:
        with self._state_lock:
            current, self._socket = self._socket, None
            self._reader = SentenceReader()
        if current is not None:
            try:
                current.close()
            except OSError:
                pass

    def _next_tag(self) -> str:
        self._tag += 1
        return str(self._tag)

    def _send(self, words: Iterable[str | bytes]) -> None:
        with self._state_lock:
            current = self._socket
        if current is None:
            raise RouterOSBinaryError("RouterOS Binary API connection is not open")
        current.sendall(encode_sentence(words))

    def _read_sentence(self, *, max_response_bytes: int | None = None) -> list[bytes]:
        if max_response_bytes is not None and max_response_bytes < 1:
            raise RouterOSBinaryError(
                "RouterOS Binary API response exceeds configured safety limit",
                failure_kind="invalid_response",
            )
        sentence_limit = MAX_SENTENCE_SIZE
        if max_response_bytes is not None:
            sentence_limit = min(sentence_limit, max_response_bytes)
        with self._state_lock:
            received = len(self._reader._buffer)  # noqa: SLF001 - account for previously read response bytes
        if max_response_bytes is not None and received > max_response_bytes:
            raise RouterOSBinaryError(
                "RouterOS Binary API response exceeds configured safety limit",
                failure_kind="invalid_response",
            )
        while True:
            # A single recv() may contain more than one sentence.  Drain the
            # persistent reader before waiting for another network read so the
            # second sentence is never discarded between API replies.
            with self._state_lock:
                current = self._socket
                if current is None:
                    raise RouterOSBinaryError("RouterOS Binary API connection is not open")
                buffered = list(
                    self._reader.feed(
                        b"", max_sentence_size=sentence_limit, max_sentences=1
                    )
                )
                if buffered:
                    sentence = buffered[0]
                    if max_response_bytes is not None and _sentence_wire_size(sentence) > max_response_bytes:
                        raise RouterOSBinaryError(
                            "RouterOS Binary API response exceeds configured safety limit",
                            failure_kind="invalid_response",
                        )
                    return sentence
            recv_size = 4096
            if max_response_bytes is not None:
                recv_size = min(recv_size, max_response_bytes - received)
                if recv_size < 1:
                    raise RouterOSBinaryError(
                        "RouterOS Binary API response exceeds configured safety limit",
                        failure_kind="invalid_response",
                    )
            chunk = current.recv(recv_size)
            if not chunk:
                raise RouterOSBinaryError("RouterOS closed the Binary API connection")
            if len(chunk) > recv_size:
                raise RouterOSBinaryError(
                    "RouterOS Binary API response exceeds configured safety limit",
                    failure_kind="invalid_response",
                )
            received += len(chunk)
            with self._state_lock:
                if self._socket is not current:
                    raise RouterOSBinaryError("RouterOS Binary API connection was closed")
                parsed = list(
                    self._reader.feed(
                        chunk,
                        max_sentence_size=sentence_limit,
                        max_sentences=1,
                    )
                )
                if parsed:
                    sentence = parsed[0]
                    if max_response_bytes is not None and _sentence_wire_size(sentence) > max_response_bytes:
                        raise RouterOSBinaryError(
                            "RouterOS Binary API response exceeds configured safety limit",
                            failure_kind="invalid_response",
                        )
                    return sentence

    def _request(self, words: Iterable[str | bytes]) -> list[RouterOSReply]:
        tag = self._next_tag()
        try:
            self._send([*words, f".tag={tag}"])
            replies: list[RouterOSReply] = []
            response_bytes = 0
            response_words = 0
            while True:
                if len(replies) >= MAX_RESPONSE_REPLIES:
                    raise RouterOSBinaryError(
                        "RouterOS Binary API response exceeds configured reply limit",
                        failure_kind="invalid_response",
                    )
                remaining_bytes = MAX_RESPONSE_BYTES - response_bytes
                sentence = self._read_sentence(max_response_bytes=remaining_bytes)
                sentence_bytes = _sentence_wire_size(sentence)
                if sentence_bytes > remaining_bytes:
                    raise RouterOSBinaryError(
                        "RouterOS Binary API response exceeds configured safety limit",
                        failure_kind="invalid_response",
                    )
                response_bytes += sentence_bytes
                response_words += len(sentence)
                if response_words > MAX_RESPONSE_WORDS:
                    raise RouterOSBinaryError(
                        "RouterOS Binary API response exceeds configured word limit",
                        failure_kind="invalid_response",
                    )
                reply = parse_reply(sentence)
                if reply.attributes.get(".tag") != tag:
                    raise RouterOSBinaryError(
                        "RouterOS Binary API reply tag did not match the active request",
                        failure_kind="invalid_response",
                    )
                replies.append(reply)
                if reply.kind in {"done", "empty", "trap", "fatal"}:
                    if reply.kind in {"trap", "fatal"}:
                        message = reply.attributes.get("message", "RouterOS rejected the Binary API request")
                        raise RouterOSBinaryError(message)
                    return replies
        except Exception:
            # Limits, malformed replies, and wrong tags leave the stream's
            # unread bytes ambiguous; never reuse that connection.
            self.close()
            raise

    def execute(self, path: str, *, query: Iterable[str] = ()) -> list[RouterOSReply]:
        """Execute one read-only ``print`` command and return its replies.

        This deliberately has no mutation verb helpers.  Callers should use
        explicit ``/resource/print`` paths and a narrow ``.proplist`` query.
        """

        if not path.startswith("/"):
            raise ValueError("RouterOS API paths must start with '/'")
        return self._request([path, *query])

    def listen(self, path: str, *, query: Iterable[str] = ()) -> Iterator[RouterOSReply]:
        """Start a RouterOS ``listen`` command and yield change records.

        The caller owns the connection and must close it to stop the stream.
        ``listen`` is intentionally exposed only as a read stream; the broker
        is responsible for reconciliation and stale/dead record handling.
        """
        if not path.startswith("/"):
            raise ValueError("RouterOS API paths must start with '/'")
        tag = self._next_tag()
        try:
            self._send([path + "/listen", *query, f".tag={tag}"])
            while True:
                reply = parse_reply(self._read_sentence())
                if reply.attributes.get(".tag") != tag:
                    raise RouterOSBinaryError(
                        "RouterOS Binary API reply tag did not match the active request",
                        failure_kind="invalid_response",
                    )
                if reply.kind in {"re", "done", "trap", "fatal"}:
                    if reply.kind in {"trap", "fatal"}:
                        message = reply.attributes.get("message", "RouterOS rejected the Binary API listen request")
                        raise RouterOSBinaryError(message)
                    if reply.kind == "done":
                        return
                    yield reply
        except Exception:
            self.close()
            raise
