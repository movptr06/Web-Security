import unit.config
from ruleset.rule import *

import unittest

class TEST(unittest.TestCase):
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

        get = HTTPRequest(HTTP_REQUEST_GET, "127.0.0.1")
        detected = rule.detect(get)

        self.assertEqual(detected.query_parameter, [("id", ['"', '"', '"', '"'])])
