import json
from pathlib import Path

from spurhund.models import Finding
from spurhund.sarif import write_sarif


def test_write_sarif_records_levels_and_allows_an_empty_run(tmp_path: Path, monkeypatch):
    findings = [
        Finding("low-rule", "Low rule", "LOW", "a.py", 4, "abcd****wxyz", 1.2, "raw"),
        Finding("custom", "Custom", "ODD", "dir\\b.py", 0, "********", 1.0, "x"),
    ]
    report = tmp_path / "nested" / "spurhund.sarif"
    write_sarif(report, findings)

    document = json.loads(report.read_text(encoding="utf-8"))
    results = document["runs"][0]["results"]
    assert document["version"] == "2.1.0"
    assert [item["level"] for item in results] == ["note", "warning"]
    assert results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "dir/b.py"
    assert results[1]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1

    empty = tmp_path / "empty.sarif"
    write_sarif(empty, [])
    assert json.loads(empty.read_text(encoding="utf-8"))["runs"][0]["results"] == []

    monkeypatch.chdir(tmp_path)
    write_sarif(Path("relative.sarif"), [])
    assert Path("relative.sarif").is_file()
