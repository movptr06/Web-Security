from ruleset.ruleset import *
from ruleset.rule import Rule
from ruleset.action import Action

from web.request import HttpRequest

import unittest

class TEST(unittest.TestCase):
    def test_detect(self):
        GET_SQL_INJECTION = """
        {
            "name": "GET_SQL_INJECTION",
            "description": "GET SQL injection attack",
            "severity": "HIGH",
            "action": "BLOCK",
            "definition": {
                "queryParameter": {
                    "*": "[\\"']"
                }
            }
        }
        """

        RULE_GET_SQL_INJECTION = Rule(GET_SQL_INJECTION)

        POST_SQL_INJECTION = """
        {
            "name": "POST_SQL_INJECTION",
            "description": "POST SQL injection attack",
            "severity": "HIGH",
            "action": "COUNT",
            "definition": {
                "jsonBody": {
                    "*": "[\\"']"
                }
            }

        }
        """

        RULE_POST_SQL_INJECTION = Rule(POST_SQL_INJECTION)

        ALLOW = """
        {
            "name": "ALLOW",
            "description": "ALLOW",
            "severity": "MEDIUM",
            "action": "ALLOW",
            "definition": {
                "header": {
                    "*": ".+"
                }
            }

        }
        """

        RULE_ALLOW = Rule(ALLOW)

        ruleset = RuleSet([
            RULE_ALLOW,
            RULE_POST_SQL_INJECTION,
            RULE_GET_SQL_INJECTION
        ])

        HTTP_REQUEST_GET = (
            b'GET /bbs/board.php?id=1"%20or%20"1"%20=%20"1 HTTP/1.1\r\n'
            b'Host: 127.0.0.1:8000\r\n'
            b'User-Agent: curl/7.68.0\r\n'
            b'Accept: */*\r\n'
            b'\r\n'
        )

        get = HttpRequest(HTTP_REQUEST_GET, "127.0.0.1")
        action, detected = ruleset.detect(get)

        self.assertEqual(action, Action.BLOCK)
        self.assertEqual(detected.query_parameter, [("id", ['"', '"', '"', '"'])])
