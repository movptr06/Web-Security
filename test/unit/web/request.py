from web.request import *

import unittest

class TEST(unittest.TestCase):
    def test_cookie(self):
        self.assertEqual(HttpRequest._cookie("a=1; b=2"), {"a": "1", "b": "2"})

    def test_query_parameter(self):
        self.assertEqual(HttpRequest._query_parameter("a=1"), {"a": ("1", )})

    def test_init(self):
        HTTP_REQUEST_GET = (
            b'GET /test?a=1 HTTP/1.1\r\n'
            b'Host: 127.0.0.1:8000\r\n'
            b'User-Agent: curl/7.68.0\r\n'
            b'Accept: */*\r\n'
            b'Cookie: A=1\r\n'
            b'\r\n'
        )

        get = HttpRequest(HTTP_REQUEST_GET, "127.0.0.1")
        self.assertEqual(get.ipv4, IPv4Address("127.0.0.1"))
        self.assertEqual(get.method, "GET")
        self.assertEqual(get.header["host"], "127.0.0.1:8000")
        self.assertEqual(get.cookie["A"], "1")
        self.assertEqual(get.url_resource, "/test")
        self.assertEqual(get.query_string, "a=1")
        self.assertEqual(get.query_parameter, {"a": ("1", )})

        HTTP_REQUEST_POST = (
            b'POST / HTTP/1.1\r\n'
            b'Host: 127.0.0.1:8000\r\n'
            b'User-Agent: curl/7.68.0\r\n'
            b'Accept: */*\r\n'
            b'Cookie: A=1\r\n'
            b'Content-Type: application/json\r\n'
            b'Content-Length: 8\r\n'
            b'\r\n'
            b'{"a": 1}'
        )

        post = HttpRequest(HTTP_REQUEST_POST, "::1")
        self.assertEqual(post.ipv6, IPv6Address("::1"))
        self.assertEqual(post.method, "POST")
        self.assertEqual(post.header["host"], "127.0.0.1:8000")        
        self.assertEqual(post.cookie["A"], "1")
        self.assertEqual(post.url_resource, "/")
        self.assertEqual(post.body, '{"a": 1}')
        self.assertEqual(post.json_body, {"a": 1})
