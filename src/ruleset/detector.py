from typing import *
from dataclasses import dataclass

from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network

from ruleset.validate import validate
from ruleset.definition import Definition

from web.request import HTTPRequest

import re

@dataclass
class Detect:
    ipv4: str
    ipv6: str
    method: str
    header: List[Tuple[str, List[str]]]
    cookie: List[Tuple[str, List[str]]]
    url_resource: List[str]
    query_string: List[str]
    query_parameter: List[Tuple[str, List[str]]]
    body: List[str]
    json_body: List[Tuple[str, List[str]]]

class Detector:
    def _ipv4(net: IPv4Network):
        def detect(data: IPv4Address):
            if data == None: return False
            return data if data in net else False
        return detect

    def _ipv6(net: IPv6Network):
        def detect(data: IPv6Address):
            if data == None: return False
            return data if data in net else False
        return detect

    def _text(text: str):
        def detect(data: str):
            if data == None: return False
            return data if data == text else False
        return detect

    def _regexp(regexp: str):
        p = re.compile(regexp)

        def detect(data: str):
            if data == None: return False
            result = p.findall(data)
            return result if result != [] else False

        return detect

    def _group(group: dict):
        # key : text
        # value : regexp
        p = [(i[0], Detector._regexp(i[1])) for i in group.items()]

        def detect(data: Dict[str, str]):
            if data == None: return False
            result = []

            for name, regexp in p:
                if name in data:
                    if validate(data[name], tuple):
                        r = regexp("".join(data[name]))
                    else:
                        r = regexp(data[name])
                    if r:
                        result.append((name, r))
                elif name == "*":
                    for key, value in data.items():
                        if validate(data[key], tuple):
                            r = regexp("".join(data[key]))
                        else:
                            r = regexp(data[key])
                        if r:
                            result.append((key, r))

            return result if result else False

        return detect

    def _object(obj: dict):
        # key : text
        # value : regexp
        p = [(i[0], Detector._regexp(i[1])) for i in obj.items()]

        def detect(data: dict):
            if data == None: return False
            data = list(data.items())

            result = []

            for key, value in data:
                if validate(value, dict):
                    data += value.items()
                    continue
                for name, regexp in p:
                    if key == name or name == "*":
                        if validate(value, tuple):
                            r = regexp("".join(value))
                        else:
                            r = regexp(value)
                        if r:
                            result.append((key, r))

            return result if result else False

        return detect

    def __init__(self, definition: Definition):
        def PASS(data):
            # None != False
            return None

        # ipv4 : ipv4
        if definition.ipv4 != None:
            self.ipv4 = Detector._ipv4(definition.ipv4)
        else:
            self.ipv4 = PASS

        # ipv6 : ipv6
        if definition.ipv6 != None:
            self.ipv6 = Detector._ipv6(definition.ipv6)
        else:
            self.ipv6 = PASS

        # method : text
        if definition.method != None:
            self.method = Detector._text(definition.method)
        else:
            self.method = PASS

        # header : group
        if definition.header != None:
            self.header = Detector._group(definition.header)
        else:
            self.header = PASS

        # cookie : group
        if definition.cookie != None:
            self.cookie = Detector._group(definition.cookie)
        else:
            self.cookie = PASS

        # url_resource : regexp
        if definition.url_resource != None:
            self.url_resource = Detector._regexp(definition.url_resource)
        else:
            self.url_resource = PASS

        # query_string : regexp
        if definition.query_string != None:
            self.query_string = Detector._regexp(definition.query_string)
        else:
            self.query_string = PASS

        # query_parameter : group
        if definition.query_parameter != None:
            self.query_parameter = Detector._group(definition.query_parameter)
        else:
            self.query_parameter = PASS

        # body : regexp
        if definition.body != None:
            self.body = Detector._regexp(definition.body)
        else:
            self.body = PASS

        # json_body : object
        if definition.json_body != None:
            self.json_body = Detector._object(definition.json_body)
        else:
            self.json_body = PASS

    def detect(self, http: HTTPRequest):
        return Detect(
            self.ipv4(http.ipv4),
            self.ipv6(http.ipv6),
            self.method(http.method),
            self.header(http.header),
            self.cookie(http.cookie),
            self.url_resource(http.url_resource),
            self.query_string(http.query_string),
            self.query_parameter(http.query_parameter),
            self.body(http.body),
            self.json_body(http.json_body)
        )

import unittest

class TEST_Detector(unittest.TestCase):
    def test_ipv4(self):
        net = IPv4Network("10.0.0.0/8")
        ipv4 = IPv4Address("10.0.0.1")
        
        self.assertEqual(Detector._ipv4(net)(ipv4), ipv4)
        self.assertFalse(Detector._ipv4(net)(IPv4Address("127.0.0.1")))

    def test_ipv6(self):
        net = IPv6Network("::1")
        ipv6 = IPv6Address("::1")
        
        self.assertEqual(Detector._ipv6(net)(ipv6), ipv6)
        self.assertFalse(Detector._ipv6(net)(IPv6Address("::")))

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
        self.assertEqual(result.ipv4(ipv4), ipv4)
        self.assertEqual(result.ipv6(ipv6), ipv6)
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

        get = HTTPRequest(HTTP_REQUEST_GET, "127.0.0.1")        
        result = detector.detect(get)

        self.assertFalse(result.ipv6)
        self.assertEqual(result.ipv4, IPv4Address("127.0.0.1"))
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

        post = HTTPRequest(HTTP_REQUEST_POST, "::1")
        result = detector.detect(post)

        self.assertFalse(result.ipv4)
        self.assertEqual(result.ipv6, IPv6Address("::1"))
        self.assertEqual(result.header, [("user-agent", ["curl"])])
        self.assertEqual(result.body, ["{", "}"])
        self.assertEqual(result.json_body, [("id", ["'", "'", "'", "'"])])
