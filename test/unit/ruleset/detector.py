from ruleset.detector import *

import unittest

class TEST(unittest.TestCase):
    def test_ipv4(self):
        net = IPv4Network("10.0.0.0/8")
        ipv4 = IPv4Address("10.0.0.1")
        
        self.assertEqual(Detector._ipv4(net)([ipv4]), [ipv4])
        self.assertFalse(Detector._ipv4(net)([IPv4Address("127.0.0.1")]))

    def test_ipv6(self):
        net = IPv6Network("::1")
        ipv6 = IPv6Address("::1")
        
        self.assertEqual(Detector._ipv6(net)([ipv6]), [ipv6])
        self.assertFalse(Detector._ipv6(net)([IPv6Address("::")]))

    def test_text(self):
        self.assertEqual(Detector._text("GET")("GET"), "GET")
        self.assertFalse(Detector._regexp("GET")("POST"))

    def test_regexp(self):
        self.assertEqual(Detector._regexp("[01]+")("test10"), ["10"])
        self.assertFalse(Detector._regexp("[01]+")("test"))

    def test_group(self):
        group = {
            "user-agent": "curl.*",
            "*": "0"
        }
        header = {
            "user-agent": "curl/7.68.0"
        }
        r = [("user-agent", ["curl/7.68.0"]), ("user-agent", ["0"])]
        
        self.assertEqual(Detector._group(group)(header), r)
        self.assertFalse(Detector._group(group)({}))

    def test_object(self):
        tmp = {
            "a": "1",
            "*": "[0-9]+"
        }
        obj = {
            "A": {
                "a": "1",
                "b": "1234"
            }
        }
        r = [("a", ["1"]), ("a", ["1"]), ("b", ["1234"])]
        
        self.assertEqual(Detector._object(tmp)(obj), r)
        self.assertFalse(Detector._object(tmp)({}))

    def test_init(self):
        header = {
            "user-agent": ".+"
        }
        cookie = {
            "PHPSESSID": "test"
        }
        query_parameter = {
            "*": "['\"]"
        }
        json_body = {
            "*": "1234"
        }
        tmp = {
            "ipv4Network": "127.0.0.1",
            "ipv6Network": "::1",
            "method": "POST",
            "header": header,
            "cookie": cookie,
            "urlResource": "/",
            "queryString": "admin",
            "queryParameter": query_parameter,
            "body": "abcd",
            "jsonBody": json_body
        }

        ipv4 = IPv4Address("127.0.0.1")
        ipv6 = IPv6Address("::1")
        result = Detector(Definition(tmp))
        self.assertEqual(result.ipv4([ipv4]), [ipv4])
        self.assertEqual(result.ipv6([ipv6]), [ipv6])
        self.assertEqual(result.method("POST"), "POST")
        self.assertEqual(result.header(header), [("user-agent", [".+"])])
        self.assertEqual(result.cookie(cookie), [("PHPSESSID", ["test"])])
        self.assertEqual(result.url_resource("/test"), ["/"])
        self.assertEqual(result.query_string("?admin=1"), ["admin"])
        
        data = {
            "id": "1'",
            "pw": '1"'
        }
        r = [("id", ["'"]), ("pw", ["\""])]
        
        self.assertEqual(result.query_parameter(data), r)
        self.assertEqual(result.body("abcdefg"), ["abcd"])
        
        data = {
            "a": {
                "1": "1234"
            },
            "b": {
                "2": "1234"
            }
        }
        r = [("1", ["1234"]), ("2", ["1234"])]
        
        self.assertEqual(result.json_body(data), r)

    def test_detect(self):
        tmp = {
            "ipv4Network": "127.0.0.0/8",
            "ipv6Network": "::1",
            "method": "GET",
            "header": {
                "User-Agent": "curl"
            },
            "cookie": {
                "admin": ".*"
            },
            "urlResource": "admin",
            "queryString": "id",
            "queryParameter": {
                "*" : "-[0-9]+"
            },
            "body": "[{}]",
            "jsonBody": {
                "*": "['\"]"
            }
        }

        detector = Detector(Definition(tmp))

        HTTP_REQUEST_GET = (
            b'GET /admin?id=-1 HTTP/1.1\r\n'
            b'Host: 127.0.0.1:8000\r\n'
            b'User-Agent: curl/7.68.0\r\n'
            b'Accept: */*\r\n'
            b'Cookie: admin=1\r\n'
            b'\r\n'
        )

        get = HttpRequest(HTTP_REQUEST_GET, "127.0.0.1")
        result = detector.detect(get)

        self.assertFalse(result.ipv6)
        self.assertEqual(result.ipv4, [IPv4Address("127.0.0.1")])
        self.assertEqual(result.method, "GET")
        self.assertEqual(result.header, [("user-agent", ["curl"])])
        self.assertEqual(result.cookie, [("admin", ["1", ""])])
        self.assertEqual(result.url_resource, ["admin"])
        self.assertEqual(result.query_string, ["id"])
        self.assertEqual(result.query_parameter, [("id", ["-1"])])

        HTTP_REQUEST_POST = (
            b'POST / HTTP/1.1\r\n'
            b'Host: 127.0.0.1:8000\r\n'
            b'User-Agent: curl/7.68.0\r\n'
            b'Accept: */*\r\n'
            b'Cookie: A=1\r\n'
            b'Content-Type: application/json\r\n'
            b'Content-Length: 8\r\n'
            b'\r\n'
            b'{"id": "1\' or \'1\' = \'1"}'
        )

        post = HttpRequest(HTTP_REQUEST_POST, "::1")
        result = detector.detect(post)

        self.assertFalse(result.ipv4)
        self.assertEqual(result.ipv6, [IPv6Address("::1")])
        self.assertEqual(result.header, [("user-agent", ["curl"])])
        self.assertEqual(result.body, ["{", "}"])
        self.assertEqual(result.json_body, [("id", ["'", "'", "'", "'"])])
