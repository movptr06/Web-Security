from log.logger import *

from ruleset.rule import Rule
from ruleset.action import Action
from ruleset.severity import Severity

from web.request import HttpRequest

import unittest

LOG = """
    {
        "name": "GET SQL injection",
        "severity": "HIGH",
        "action": "BLOCK",
        "ipAddress": {
            "ipv4Address": [
                "127.0.0.1"
            ],
            "ipv6Address": []
        },
        "detected": {
            "query_parameter": [
                [
                    "id",
                    [
                        "\\"",
                        "\\"",
                        "\\"",
                        "\\""
                    ]
                ]
            ]
        },
        "httpRequest": {
            "method": "GET",
            "header": {
                "Host": "127.0.0.1:8000",
                "User-Agent": "curl/7.68.0",
                "Accept": "*/*"
            },
            "cookie": null,
            "urlResource": "/bbs/board.php",
            "queryString": "id=1\\"%20or%20\\"1\\"%20=%20\\"1",
            "queryParameter": {
                "id": [
                    "1\\" or \\"1\\" = \\"1"
                ]
            },
            "body": "",
            "jsonBody": null
        }
    }
"""[1:-1]

class TEST(unittest.TestCase):
    def _out(self, data):
        self.save = data

    def test_init(self):
        query_parameter = {
            "*": "[\"']"
        }
        tmp = """
        {
            "name": "GET SQL injection",
            "description": "GET SQL injection attack",
            "severity": "high",
            "action": "block",
            "definition": {
                "queryParameter": {
                    "*": "[\\"']"
                }
            }
        }
        """

        rule = Rule(tmp)
        
        self.assertEqual(rule.name, "GET SQL injection")
        self.assertEqual(rule.description, "GET SQL injection attack")
        self.assertEqual(rule.severity, Severity.HIGH)
        self.assertEqual(rule.action, Action.BLOCK)
        self.assertEqual(rule.definition.query_parameter, query_parameter)

        HTTP_REQUEST_GET = (
            b'GET /bbs/board.php?id=1"%20or%20"1"%20=%20"1 HTTP/1.1\r\n'
            b'Host: 127.0.0.1:8000\r\n'
            b'User-Agent: curl/7.68.0\r\n'
            b'Accept: */*\r\n'
            b'\r\n'
        )

        get = HttpRequest(HTTP_REQUEST_GET, "127.0.0.1")
        detected = rule.detect(get)

        logger = Logger(self._out)
        logger.detected(get, rule, detected)

        self.assertEqual(self.save, LOG)
