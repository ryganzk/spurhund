from dataclasses import dataclass, field
from typing import List

@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    prefixes: List[str]
    regex_pattern: str
    min_entropy: float = 0.0
    capture_group: int = 0
    exclude_values: List[str] = field(default_factory=list)
    path_excludes: List[str] = field(default_factory=list)

@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    masked_secret: str
    entropy: float
    raw_match: str