from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityFinding:
    tool: str
    severity: str
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    rule_id: Optional[str] = None

    def to_dict(self):
        return {
            "tool": self.tool,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
        }
