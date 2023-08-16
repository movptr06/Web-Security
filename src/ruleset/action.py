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
