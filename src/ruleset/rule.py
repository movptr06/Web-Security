import json

from ruleset.validate import check
from ruleset.action import Action
from ruleset.severity import Severity
from ruleset.definition import Definition
from ruleset.detector import Detector

class Rule():
    def __init__(self, json_ruleset: str):
        rule = json.loads(json_ruleset)

        assert check(rule, "name", str)
        assert check(rule, "description", str)
        assert check(rule, "severity", str)
        assert check(rule, "action", str)
        assert check(rule, "definition", dict)

        self.name = rule["name"]
        self.description = rule["description"]
        self.severity = Severity.serialize(rule["severity"])
        self.action = Action.serialize(rule["action"])
        self.definition = Definition(rule["definition"])

        self.detector = Detector(self.definition)
        self.detect = self.detector.detect
