from typing import *

from ruleset.rule import Rule
from ruleset.action import Action

from web.request import HttpRequest

class RuleSet:
    def __init__(self, rules: List[Rule]):
        self.ruleset = rules
        self.rules = []

        for rule in rules:
            if rule.action != Action.ALLOW:
                self.rules.append(rule)

    def detect(self, http: HttpRequest):
        for rule in self.rules:
            detected = rule.detect(http)
            if detected:
                return (rule.action, detected)
        return False
