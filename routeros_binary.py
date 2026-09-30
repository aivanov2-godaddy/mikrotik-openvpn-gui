"""Small, dependency-free RouterOS Binary API transport primitives.

The live-telemetry migration starts with a read-only protocol layer.  This
module deliberately does not expose RouterOS credentials to callers outside
the dashboard process and does not contain any configuration-mutating
helpers.  The production telemetry broker will build on these primitives in a
later, separately reviewable change.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass
from typing import Iterable, Iterator


class RouterOSBinaryError(RuntimeError):
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


def decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
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
    values = list(words)
    if not values or not values[0].startswith(b"!"):
        raise RouterOSBinaryError("RouterOS reply does not have a reply kind")
    kind = values[0].decode("utf-8", "replace")[1:]
    attributes: dict[str, str] = {}
    for raw in values[1:]:
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
    return RouterOSReply(kind, attributes)


class SentenceReader:
    """Incrementally decode API sentences from a TCP byte stream."""

    def __init__(self, *, max_word_size: int = 1 << 20) -> None:
        self._buffer = bytearray()
        self.max_word_size = max_word_size

    def feed(self, data: bytes) -> Iterator[list[bytes]]:
        self._buffer.extend(data)
        while True:
            offset = 0
            words: list[bytes] = []
            complete = False
            while True:
                try:
                    length, next_offset = decode_length(bytes(self._buffer), offset)
                except RouterOSBinaryError:
                    break
                if length == 0:
                    del self._buffer[:next_offset]
                    complete = True
                    break
                if length > self.max_word_size:
                    raise RouterOSBinaryError("RouterOS API word exceeds configured safety limit")
                end = next_offset + length
                if end > len(self._buffer):
                    break
                words.append(bytes(self._buffer[next_offset:end]))
                offset = end
            if not complete:
                return
            yield words


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
        self.host = host
        self.port = port
        self.timeout = timeout
        self.insecure_tls = insecure_tls
        self.ca_file = ca_file
        self._socket: socket.socket | ssl.SSLSocket | None = None
        self._tag = 0

    def connect(self, username: str, password: str) -> None:
        if self._socket is not None:
            return
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.insecure_tls:
            context = ssl._create_unverified_context()  # noqa: SLF001 - explicit test-only option
        else:
            context = ssl.create_default_context(cafile=self.ca_file)
        wrapped = context.wrap_socket(raw, server_hostname=self.host)
        wrapped.settimeout(self.timeout)
        self._socket = wrapped
        replies = self._request(["/login", f"=name={username}", f"=password={password}"])
        # RouterOS v6 and some compatibility modes return a challenge from the
        # first login request.  Complete that legacy handshake without ever
        # exposing the password to callers or logs.  RouterOS v7 normally
        # completes the one-step request and therefore has no ``ret`` value.
        challenge = next(
            (reply.attributes.get("ret") for reply in replies if reply.kind == "done"),
            None,
        )
        if challenge:
            self._request(
                [
                    "/login",
                    f"=name={username}",
                    f"=response={challenge_response(password, challenge)}",
                ]
            )

    def close(self) -> None:
        current, self._socket = self._socket, None
        if current is not None:
            try:
                current.close()
            except OSError:
                pass

    def _next_tag(self) -> str:
        self._tag += 1
        return str(self._tag)

    def _send(self, words: Iterable[str | bytes]) -> None:
        if self._socket is None:
            raise RouterOSBinaryError("RouterOS Binary API connection is not open")
        self._socket.sendall(encode_sentence(words))

    def _read_sentence(self) -> list[bytes]:
        if self._socket is None:
            raise RouterOSBinaryError("RouterOS Binary API connection is not open")
        reader = SentenceReader()
        while True:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise RouterOSBinaryError("RouterOS closed the Binary API connection")
            for sentence in reader.feed(chunk):
                return sentence

    def _request(self, words: Iterable[str | bytes]) -> list[RouterOSReply]:
        tag = self._next_tag()
        self._send([*words, f".tag={tag}"])
        replies: list[RouterOSReply] = []
        while True:
            reply = parse_reply(self._read_sentence())
            replies.append(reply)
            if reply.kind in {"done", "empty", "trap", "fatal"}:
                if reply.kind in {"trap", "fatal"}:
                    message = reply.attributes.get("message", "RouterOS rejected the Binary API request")
                    raise RouterOSBinaryError(message)
                return replies

    def listen(self, path: str, *, query: Iterable[str] = ()) -> Iterator[RouterOSReply]:
        """Start a RouterOS ``listen`` command and yield change records.

        The caller owns the connection and must close it to stop the stream.
        ``listen`` is intentionally exposed only as a read stream; the broker
        is responsible for reconciliation and stale/dead record handling.
        """
        if not path.startswith("/"):
            raise ValueError("RouterOS API paths must start with '/'")
        tag = self._next_tag()
        self._send([path + "/listen", *query, f".tag={tag}"])
        while True:
            reply = parse_reply(self._read_sentence())
            if reply.kind in {"re", "done", "trap", "fatal"}:
                if reply.kind in {"trap", "fatal"}:
                    message = reply.attributes.get("message", "RouterOS rejected the Binary API listen request")
                    raise RouterOSBinaryError(message)
                if reply.kind == "done":
                    return
                yield reply


def challenge_response(password: str, challenge_hex: str) -> str:
    """Return the legacy RouterOS two-step login response."""
    try:
        challenge = bytes.fromhex(challenge_hex)
    except ValueError as error:
        raise RouterOSBinaryError("RouterOS returned an invalid login challenge") from error
    digest = hashlib.md5(b"\x00" + password.encode("utf-8") + challenge).hexdigest()
    return digest
