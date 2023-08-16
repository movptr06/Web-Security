import enum

class Action(enum.Enum):
    ALLOW = enum.auto()
    COUNT = enum.auto()
    BLOCK = enum.auto()

    def serialize(action_name: str):
        action_name = action_name.upper()
        for action in Action:
            if action.name == action_name:
                return action

    def deserialize(action: enum.Enum):
        return action.name.upper()

import unittest

class TEST_Action(unittest.TestCase):
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
