from ruleset.ruleset import RuleSet
from ruleset.action import Action

from web.request import HttpRequest

class Handler:
    def __init__(self, ruleset: RuleSet, logger):
        self.ruleset = ruleset
        self.logger = logger

    def handler(self, data: bytes, ip):
        http = HttpRequest(data, ip)
        action, detected = self.ruleset.detect(http)
        if detected:
            self.logger(http, action, detected)
        return action != Action.BLOCK
