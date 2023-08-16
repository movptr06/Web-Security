import unit.config
from ruleset.severity import *

import unittest

class TEST(unittest.TestCase):
    def test_serialize(self):
        self.assertEqual(Severity.serialize("critical"), Severity.CRITICAL)
        self.assertEqual(Severity.serialize("high"), Severity.HIGH)
        self.assertEqual(Severity.serialize("medium"), Severity.MEDIUM)
        self.assertEqual(Severity.serialize("low"), Severity.LOW)
        
        self.assertEqual(Severity.serialize("CRITICAL"), Severity.CRITICAL)
        self.assertEqual(Severity.serialize("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.serialize("MEDIUM"), Severity.MEDIUM)
        self.assertEqual(Severity.serialize("LOW"), Severity.LOW)

    def test_deserialize(self):
        self.assertEqual(Severity.deserialize(Severity.CRITICAL), "CRITICAL")
        self.assertEqual(Severity.deserialize(Severity.HIGH), "HIGH")
        self.assertEqual(Severity.deserialize(Severity.MEDIUM), "MEDIUM")
        self.assertEqual(Severity.deserialize(Severity.LOW), "LOW")
