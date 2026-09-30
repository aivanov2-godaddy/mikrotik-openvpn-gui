from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
