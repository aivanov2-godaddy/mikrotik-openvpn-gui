from __future__ import annotations

import asyncio
import socket
import unittest

from asgi import DashboardHTTPASGI


class ASGIContractTests(unittest.TestCase):
    def test_http_adapter_preserves_cookie_and_body_without_hop_by_hop_headers(self) -> None:
        request = DashboardHTTPASGI._request_bytes(
            {
                "method": "POST",
                "raw_path": b"/api/example",
                "query_string": b"a=1",
                "headers": [
                    (b"host", b"dashboard.example"),
                    (b"cookie", b"vpn_session=opaque"),
                    (b"connection", b"keep-alive"),
                    (b"transfer-encoding", b"chunked"),
                ],
            },
            b"{}",
        )
        self.assertIn(b"POST /api/example?a=1 HTTP/1.1", request)
        self.assertIn(b"cookie: vpn_session=opaque", request)
        self.assertIn(b"Content-Length: 2", request)
        self.assertNotIn(b"keep-alive", request)
        self.assertNotIn(b"chunked", request)

    def test_stream_response_finishes_from_content_length_without_socket_eof(self) -> None:
        client, server = socket.socketpair()
        messages: list[dict[str, object]] = []

        async def send(message: dict[str, object]) -> None:
            messages.append(message)

        try:
            server.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 5\r\n"
                b"Connection: keep-alive\r\n\r\n"
                b"hello"
            )
            response = DashboardHTTPASGI._stream_response(client, send)
            self.assertIsNotNone(response)
            asyncio.run(response)
        finally:
            client.close()
            server.close()

        self.assertEqual(messages[0]["type"], "http.response.start")
        self.assertEqual(messages[1], {"type": "http.response.body", "body": b"hello", "more_body": True})
        self.assertEqual(messages[2], {"type": "http.response.body", "body": b""})


if __name__ == "__main__":
    unittest.main()
