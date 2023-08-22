from ruleset.ruleset import RuleSet
from ruleset.action import Action

from web.request import HttpRequest

class Handler:
    def __init__(self, ruleset: RuleSet, allow, logger):
        self.ruleset = ruleset
        self.allow = allow
        self.logger = logger

    def handler(self, data: bytes, ip):
        http = HttpRequest(data, ip)

        if self.allow(
            ip,
            http.ipv4,
            http.ipv6,
            http.header["user-agent"]
            ):
            return True

        action, detected = self.ruleset.detect(http)
        if detected:
            self.logger(http, action, detected)
        return action != Action.BLOCK
