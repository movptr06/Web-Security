from ruleset.definition import *

import unittest

class TEST(unittest.TestCase):
    def test_ipv4(self):
        tmp = {
            "ipv4Network": "10.0.0.0/8"
        }
        r = IPv4Network("10.0.0.0/8")
        self.assertEqual(Definition._ipv4(tmp, "ipv4Network"), r)

    def test_ipv6(self):
        tmp = {
            "ipv6Network": "::1"
        }
        r = IPv6Network("0::1")
        self.assertEqual(Definition._ipv6(tmp, "ipv6Network"), r)

    def test_str(self):
        tmp = {
            "method": "PUT"
        }
        self.assertEqual(Definition._str(tmp, "method"), "PUT")

    def test_group(self):
        group = {
            "a": "b"
        }
        tmp = {
            "group": group
        }
        self.assertEqual(Definition._group(tmp, "group"), group)

    def test_header(self):
        header = {
            "User-Agent": ".*"
        }
        tmp = {
            "header": header
        }
        result = {
            "user-agent": ".*"
        }
        self.assertEqual(Definition._header(tmp, "header"), result)

    def test_init(self):
        header = {
            "user-agent": ".*"
        }
        cookie = {
            "PHPSESSID": "test"
        }
        query_parameter = {
            "*": "id"
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
        result = Definition(tmp)
        self.assertEqual(result.ipv4, IPv4Network("127.0.0.1"))
        self.assertEqual(result.ipv6, IPv6Network("0::1"))
        self.assertEqual(result.method, "POST")
        self.assertEqual(result.header, header)
        self.assertEqual(result.cookie, cookie)
        self.assertEqual(result.url_resource, "/")
        self.assertEqual(result.query_parameter, query_parameter)
        self.assertEqual(result.body, "abcd")
        self.assertEqual(result.json_body, json_body)
