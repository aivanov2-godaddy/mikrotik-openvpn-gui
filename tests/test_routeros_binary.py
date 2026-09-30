import unittest

from routeros_binary import (
    RouterOSBinaryError,
    SentenceReader,
    challenge_response,
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

    def test_legacy_challenge_response(self) -> None:
        self.assertEqual(
            challenge_response("password", "00112233445566778899aabbccddeeff"),
            "d0a8f0f594fc4d13cf44a9fd3ea65963",
        )


if __name__ == "__main__":
    unittest.main()
