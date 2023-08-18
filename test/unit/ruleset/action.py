from ruleset.action import *

import unittest

class TEST(unittest.TestCase):
    def test_serialize(self):
        self.assertEqual(Action.serialize("allow"), Action.ALLOW)
        self.assertEqual(Action.serialize("count"), Action.COUNT)
        self.assertEqual(Action.serialize("block"), Action.BLOCK)

        self.assertEqual(Action.serialize("ALLOW"), Action.ALLOW)
        self.assertEqual(Action.serialize("COUNT"), Action.COUNT)
        self.assertEqual(Action.serialize("BLOCK"), Action.BLOCK)

    def test_deserialize(self):
        self.assertEqual(Action.deserialize(Action.ALLOW), "ALLOW")
        self.assertEqual(Action.deserialize(Action.COUNT), "COUNT")
        self.assertEqual(Action.deserialize(Action.BLOCK), "BLOCK")
