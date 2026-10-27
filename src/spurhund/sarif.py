import json
from pathlib import Path

from spurhund.models import Finding

_SARIF_LEVEL = {
    "CRITICAL": "error",
    "BLOCKER": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def write_sarif(path: str | Path, findings: list[Finding]) -> None:
    """Write findings as a SARIF 2.1.0 report. An empty list is a valid run."""
    rules: dict[str, dict] = {}
    results = []
    for finding in findings:
        level = _SARIF_LEVEL.get(finding.severity.upper(), "warning")
        rules.setdefault(finding.rule_id, {
            "id": finding.rule_id,
            "name": finding.rule_name,
            "shortDescription": {"text": finding.rule_name},
            "defaultConfiguration": {"level": level},
        })
        results.append({
            "ruleId": finding.rule_id,
            "level": level,
            "message": {"text": f"{finding.severity} {finding.rule_name}: {finding.masked_secret}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path.replace("\\", "/")},
                    "region": {"startLine": max(finding.line_number, 1)},
                }
            }],
        })

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Spurhund",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    destination = Path(path)
    if destination.parent != Path("."):
        destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
