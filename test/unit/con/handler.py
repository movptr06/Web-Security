from con.handler import *

from ruleset.ruleset import RuleSet
from ruleset.rule import Rule

from web.request import HttpRequest

import unittest

class TEST(unittest.TestCase):
    def _logger(self, http, action, detected):
        self.save = (http, action, detected)

    def test_detect(self):
        self.save = False

        tmp = """
        {
            "name": "192.168.35.*",
            "description": "192.168.35.*",
            "severity": "LOW",
            "action": "BLOCK",
            "definition": {
                "ipv4Network": "192.168.35.0/24"
            }
        }
        """

        rule = Rule(tmp)
        ruleset = RuleSet([
            rule
        ])

        handler = Handler(ruleset, self._logger)

        HTTP_REQUEST_GET = (
            b'GET /bbs/board.php?id=1"%20or%20"1"%20=%20"1 HTTP/1.1\r\n'
            b'Host: 127.0.0.1:8000\r\n'
            b'User-Agent: curl/7.68.0\r\n'
            b'Accept: */*\r\n'
            b'X-Forwarded-For: 192.168.35.0\r\n'
            b'\r\n'
        )

        result = handler.handler(HTTP_REQUEST_GET, "127.0.0.1")

        self.assertFalse(result)

        http, action, detected = self.save

        http_request = HttpRequest(HTTP_REQUEST_GET, "127.0.0.1")
        self.assertEqual(dict(http.header), dict(http_request.header))
