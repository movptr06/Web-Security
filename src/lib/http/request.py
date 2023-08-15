from ipaddress import IPv4Address, IPv6Address, AddressValueError
from http.server import BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs
from io import BytesIO

import json

class HTTPRequest(BaseHTTPRequestHandler):
    def _cookie(cookie: str):
        cookies = SimpleCookie()
        cookies.load(cookie)
        return {k: v.value for k, v in cookies.items()}

    def _query_parameter(query_string: str):
        query_parameter = {}
        for k, v in parse_qs(query_string).items():
            query_parameter[k] = tuple(v)
        return query_parameter

    def __init__(self, request_text, ip):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.parse_request()

        try:
            self.ipv4 = IPv4Address(ip)
            self.ipv6 = None
        except AddressValueError:
            self.ipv4 = None
            self.ipv6 = IPv6Address(ip)

        self.method = self.command
        self.header = self.headers

        if "cookie" in self.headers:
            self.cookie = HTTPRequest._cookie(self.headers["cookie"])
        else:
            self.cookie = None

        self.url_resource = urlparse(self.path).path
        self.query_string = urlparse(self.path).query
       
        self.query_parameter = HTTPRequest._query_parameter(self.query_string)

        self.body = self.rfile.read().decode("latin1")

        try:
            self.json_body = json.loads(self.body)
        except ValueError:
            self.json_body = None

import unittest

class TEST_HTTPRequest(unittest.TestCase):
    def test_cookie(self):
        self.assertEqual(HTTPRequest._cookie("a=1; b=2"), {"a": "1", "b": "2"})

    def test_query_parameter(self):
        self.assertEqual(HTTPRequest._query_parameter("a=1"), {"a": ("1", )})

    def test_init(self):
        HTTP_REQUEST_GET = (
            b'GET /test?a=1 HTTP/1.1\r\n'
            b'Host: 127.0.0.1:8000\r\n'
            b'User-Agent: curl/7.68.0\r\n'
            b'Accept: */*\r\n'
            b'Cookie: A=1\r\n'
            b'\r\n'
        )

        get = HTTPRequest(HTTP_REQUEST_GET, "127.0.0.1")
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

        post = HTTPRequest(HTTP_REQUEST_POST, "::1")
        self.assertEqual(post.ipv6, IPv6Address("::1"))
        self.assertEqual(post.method, "POST")
        self.assertEqual(post.header["host"], "127.0.0.1:8000")        
        self.assertEqual(post.cookie["A"], "1")
        self.assertEqual(post.url_resource, "/")
        self.assertEqual(post.body, '{"a": 1}')
        self.assertEqual(post.json_body, {"a": 1})

if __name__ == "__main__":
    unittest.main()
