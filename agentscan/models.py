from dataclasses import asdict, dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value}") from None


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    file: str
    line: int = 0
    evidence: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d
