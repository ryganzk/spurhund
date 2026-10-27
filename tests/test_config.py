from pathlib import Path

import pytest

from spurhund.config import init_config, load_config, load_raw_config, parse_gitignore, update_ignore_path


def test_init_imports_gitignore_and_ignore_updates_are_idempotent(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("# comment\n/build-artifacts/\n", encoding="utf-8")
    config_path = tmp_path / ".spurhund-rules.yml"

    created, added = init_config(tmp_path, config_path)
    assert created is True
    assert added > 0

    created_again, added_again = init_config(tmp_path, config_path)
    assert created_again is False
    assert added_again == 0

    text = config_path.read_text(encoding="utf-8")
    assert "build-artifacts/**" in text

    assert update_ignore_path(config_path, "dist/**", "add") is True
    assert update_ignore_path(config_path, "dist/**", "add") is False
    assert update_ignore_path(config_path, "dist/**", "remove") is True
    assert update_ignore_path(config_path, "dist/**", "remove") is False

    ignores, rules = load_config(config_path)
    assert "dist/**" not in ignores
    assert rules

    assert update_ignore_path(config_path, "dist/**", "noop") is False


def test_gitignore_shapes_and_missing_config(tmp_path: Path):
    assert parse_gitignore(tmp_path / "missing.gitignore") == []

    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("\n# note\nlocal.env\n", encoding="utf-8")
    assert "local.env/**" in parse_gitignore(gitignore)

    config_path = tmp_path / ".spurhund-rules.yml"
    created, added = init_config(tmp_path, config_path)
    assert created is True
    assert added > 0

    with pytest.raises(FileNotFoundError):
        load_raw_config(tmp_path / "absent.yml")
