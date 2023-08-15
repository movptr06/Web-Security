from ipaddress import IPv4Network, IPv6Network

from lib.ruleset.validate import check, validate

class Definition:
    def _ipv4(definition: dict, name: str):
        if name in definition:
            assert validate(definition[name], str)
            return IPv4Network(definition[name])
        else:
            return None

    def _ipv6(definition: dict, name: str):
        if name in definition:
            assert validate(definition[name], str)
            return IPv6Network(definition[name])
        else:
            return None

    def _str(definition: dict, name: str):
        if name in definition:
            assert validate(definition[name], str)
            return definition[name]
        else:
            return None

    def _group(definition: dict, name: str):
        if name in definition:
            assert check(definition, name, dict)
            
            for item in definition[name].items():
                assert validate(item[0], str)
                assert validate(item[1], str)
            
            return definition[name]
        else:
            return None

    def _header(definition: dict, name: str):
        if name in definition:
            assert check(definition, name, dict)

            result = {}

            for item in definition[name].items():
                assert validate(item[0], str)
                assert validate(item[1], str)
                
                result[item[0].lower()] = item[1]

            return result
        else:
            return None

    def __init__(self, definition: dict):
        self.ipv4 = Definition._ipv4(definition, "ipv4Network")
        self.ipv6 = Definition._ipv6(definition, "ipv6Network")
        self.method = Definition._str(definition, "method")
        self.header = Definition._header(definition, "header")
        self.cookie = Definition._group(definition, "cookie")
        self.url_resource = Definition._str(definition, "urlResource")
        self.query_string = Definition._str(definition, "queryString")
        self.query_parameter = Definition._group(definition, "queryParameter")
        self.body = Definition._str(definition, "body")
        self.json_body = Definition._group(definition, "jsonBody")

import unittest

class TEST_Definition(unittest.TestCase):
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
