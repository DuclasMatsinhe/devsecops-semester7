
from dataclasses import dataclass, field
from typing import List, Optional

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


@dataclass
class ScannerResult:
    """Represents the execution outcome of a security scanner."""
    tool: str
    status: str
    findings: List[SecurityFinding] = field(default_factory=list)
    error: Optional[str] = None
    return_code: Optional[int] = None

    def __post_init__(self):
        allowed_statuses = {"SUCCESS", "ERROR"}
        if self.status not in allowed_statuses:
            raise ValueError(
                f"Invalid scanner status: {self.status}. "
                f"Expected one of {sorted(allowed_statuses)}."
            )

        if self.status == "SUCCESS" and self.error is not None:
            raise ValueError("A successful scan cannot contain an error.")

        if self.status == "ERROR" and not self.error:
            raise ValueError("A failed scan must include an error message.")

    def to_dict(self):
        return {
            "tool": self.tool,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
            "error": self.error,
            "return_code": self.return_code,
        }
