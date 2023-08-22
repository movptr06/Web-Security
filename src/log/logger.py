import json

from ruleset.severity import Severity
from ruleset.action import Action

class Logger:
    def __init__(self, output):
        self.output = output

    def detected(self, http, rule, detected):
        log = [{
            "name": rule.name,
            "severity": Severity.deserialize(rule.severity),
            "action": Action.deserialize(rule.action),
            "ipAddress": {
                "ipv4Address": [str(x) for x in http.ipv4],
                "ipv6Address": [str(x) for x in http.ipv6]
            },
            "detected": detected.logfmt(),
            "httpRequest": {
                "method": http.method,
                "header": dict(http.header),
                "cookie": http.cookie,
                "urlResource": http.url_resource,
                "queryString": http.query_string,
                "queryParameter": http.query_parameter,
                "body": http.body,
                "jsonBody": http.json_body
            }
        }]
        self.output(
            json.dumps(log, ensure_ascii=False, indent=4)[2:-2]
        )
