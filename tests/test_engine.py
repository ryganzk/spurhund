from pathlib import Path

import pytest

from spurhund.config import load_config
from spurhund.core.engine import ScannerEngine
from spurhund.models import Rule
from spurhund.core.entropy import calculate_shannon_entropy
from spurhund.core.filter import is_binary_file, should_ignore_path

from tests.support import LEAK_LINE, RULES


def test_entropy_is_zero_for_empty_input():
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("abc") > 0


def test_ignore_and_binary_gates(tmp_path: Path, monkeypatch):
    assert should_ignore_path("dist/app.js", ["dist/**"])
    assert should_ignore_path("vendor", ["vendor/**"])
    assert not should_ignore_path("src/app.py", [".git/**"])

    text = tmp_path / "note.txt"
    text.write_text("hello", encoding="utf-8")
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"abc\x00def")
    assert not is_binary_file(text)
    assert is_binary_file(binary)
    assert is_binary_file(tmp_path)

    def denied(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("builtins.open", denied)
    with pytest.raises(PermissionError):
        is_binary_file(text)


def test_engine_reports_a_secret_and_skips_suppressions():
    _, rules = load_config(RULES)
    engine = ScannerEngine(rules)
    text = "\n".join([
        LEAK_LINE,
        "print('fine')",
        LEAK_LINE + "  # spurhund:ignore",
        'api_key = "dummy_mock_secret_key_placeholder_value"',
        'api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaa"',
    ])

    findings = engine.scan_text(text, file_path="app.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "sec-generic-key"
    assert findings[0].line_number == 1
    assert findings[0].masked_secret != LEAK_LINE


def test_engine_skips_rule_path_excludes():
    _, rules = load_config(RULES)
    findings = ScannerEngine(rules).scan_text(LEAK_LINE, file_path="tests/test_app.py")
    assert findings == []


def _token_rule(rule_id: str, severity: str, group: int) -> Rule:
    return Rule(
        id=rule_id,
        name=rule_id,
        severity=severity,
        prefixes=["token"],
        regex_pattern=r"token=([A-Za-z0-9]+)",
        min_entropy=0,
        capture_group=group,
    )


def test_engine_falls_back_when_the_capture_group_is_missing_and_keeps_the_higher_severity():
    token = "token=AbCdEfGh1234"
    fallback = ScannerEngine([_token_rule("bad-group", "LOW", 3)]).scan_text(token, file_path="app.py")
    assert len(fallback) == 1
    assert fallback[0].raw_match == token

    low_then_high = ScannerEngine([
        _token_rule("low", "LOW", 1),
        _token_rule("high", "CRITICAL", 1),
    ]).scan_text(token, file_path="app.py")
    assert [item.rule_id for item in low_then_high] == ["high"]

    high_then_low = ScannerEngine([
        _token_rule("high", "CRITICAL", 1),
        _token_rule("low", "LOW", 1),
    ]).scan_text(token, file_path="app.py")
    assert [item.rule_id for item in high_then_low] == ["high"]
