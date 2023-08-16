import enum

class Severity(enum.Enum):
    CRITICAL = enum.auto()
    HIGH = enum.auto()
    MEDIUM = enum.auto()
    LOW = enum.auto()

    def serialize(severity_name: str):
        severity_name = severity_name.upper()
        for severity in Severity:
            if severity.name == severity_name:
                return severity

    def deserialize(severity: enum.Enum):
        return severity.name.upper()
