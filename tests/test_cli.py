import json
import tempfile
from pathlib import Path

from spurhund.cli import app

from tests.support import LEAK_LINE, RULES, commit_all, git, init_repo


def _rules_args() -> list[str]:
    return ["--config", str(RULES)]


def test_scan_file_exit_codes(tmp_path: Path, runner, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    # Keep the fixture out of pytest's test_* directory. The generic-key rule
    # skips paths that match **/test_*.py, and * crosses slashes.
    work = Path(tempfile.mkdtemp(prefix="spurhund-"))
    clean = work / "clean.py"
    clean.write_text("print('hello')\n", encoding="utf-8")
    leak = work / "leak.py"
    leak.write_text(LEAK_LINE + "\n", encoding="utf-8")

    clean_result = runner.invoke(app, ["scan-file", str(clean), *_rules_args()])
    assert clean_result.exit_code == 0

    leak_result = runner.invoke(app, ["scan-file", str(leak), *_rules_args()])
    assert leak_result.exit_code == 1
    assert "sec-generic-key" in leak_result.output
    assert "::error " not in leak_result.output

    missing = runner.invoke(app, ["scan-file", str(work / "missing.py"), *_rules_args()])
    assert missing.exit_code == 2
    assert "File not found" in missing.output

    bad_config = tmp_path / "bad.yml"
    bad_config.write_text("rules: [\n", encoding="utf-8")
    invalid = runner.invoke(app, ["scan-file", str(clean), "--config", str(bad_config)])
    assert invalid.exit_code == 2

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    annotated = runner.invoke(app, ["scan-file", str(leak), *_rules_args()])
    assert annotated.exit_code == 1
    assert "::error " in annotated.output
    assert "title=sec-generic-key" in annotated.output

    flagged = runner.invoke(app, ["scan-file", str(leak), "--github-annotations", *_rules_args()])
    assert flagged.exit_code == 1
    assert "::error " in flagged.output


def test_scan_repo_and_staged_contracts(tmp_path: Path, runner):
    repo = tmp_path / "repo"
    init_repo(repo)
    (repo / "clean.py").write_text("print('hello')\n", encoding="utf-8")
    commit_all(repo, "base")

    clean = runner.invoke(app, ["scan-repo", str(repo), *_rules_args()])
    assert clean.exit_code == 0

    (repo / "leak.py").write_text(LEAK_LINE + "\n", encoding="utf-8")
    dirty = runner.invoke(app, ["scan-repo", str(repo), *_rules_args()])
    assert dirty.exit_code == 1

    missing = runner.invoke(app, ["scan-repo", str(tmp_path / "nope"), *_rules_args()])
    assert missing.exit_code == 2

    staged = runner.invoke(app, ["scan-staged", str(repo), *_rules_args()])
    assert staged.exit_code == 0

    git(repo, "add", "leak.py")
    leaked_index = runner.invoke(app, ["scan-staged", str(repo), *_rules_args()])
    assert leaked_index.exit_code == 1
    assert "leak.py" in leaked_index.output

    not_a_repo = runner.invoke(app, ["scan-staged", str(tmp_path), *_rules_args()])
    assert not_a_repo.exit_code == 2
    assert "not a git repository" in not_a_repo.output.lower()


def test_scan_ci_reads_the_branch_range_and_falls_back(tmp_path: Path, runner):
    repo = tmp_path / "repo"
    init_repo(repo)
    (repo / "base.py").write_text(LEAK_LINE + "\n", encoding="utf-8")
    (repo / "keep.py").write_text("print('base')\n", encoding="utf-8")
    commit_all(repo, "base")

    git(repo, "checkout", "-b", "feature")
    (repo / "dummy.py").write_text(
        'note = "not a secret"\nother = "still fine"\n' + LEAK_LINE + "\n",
        encoding="utf-8",
    )
    commit_all(repo, "branch secret")

    result = runner.invoke(
        app,
        ["scan-ci", str(repo), "--base-ref", "main", "--head-ref", "HEAD", *_rules_args()],
    )
    assert result.exit_code == 1
    assert "dummy.py:3" in result.output
    assert "base.py" not in result.output

    clean_repo = tmp_path / "clean"
    init_repo(clean_repo)
    (clean_repo / "keep.py").write_text("print('hello')\n", encoding="utf-8")
    commit_all(clean_repo, "base")
    git(clean_repo, "checkout", "-b", "feature")
    (clean_repo / "note.py").write_text("print('change')\n", encoding="utf-8")
    commit_all(clean_repo, "change")

    clean = runner.invoke(
        app,
        ["scan-ci", str(clean_repo), "--base-ref", "main", "--head-ref", "HEAD", *_rules_args()],
    )
    assert clean.exit_code == 0

    fallback = runner.invoke(
        app,
        ["scan-ci", str(clean_repo), "--base-ref", "no-such-ref", "--head-ref", "HEAD", *_rules_args()],
    )
    assert fallback.exit_code == 0
    assert "Falling back" in fallback.output

    report = tmp_path / "reports" / "spurhund.sarif"
    with_report = runner.invoke(
        app,
        ["scan-ci", str(repo), "--base-ref", "main", "--head-ref", "HEAD", "--sarif", str(report), *_rules_args()],
    )
    assert with_report.exit_code == 1
    document = json.loads(report.read_text(encoding="utf-8"))
    result = document["runs"][0]["results"][0]
    assert result["ruleId"] == "sec-generic-key"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3

    blocked = runner.invoke(
        app,
        ["scan-ci", str(repo), "--base-ref", "main", "--sarif", str(tmp_path), *_rules_args()],
    )
    assert blocked.exit_code == 2
    assert "Unable to write SARIF report" in blocked.output


def test_init_and_ignore_commands(tmp_path: Path, runner):
    (tmp_path / ".gitignore").write_text("generated/\n", encoding="utf-8")
    created = runner.invoke(app, ["init", "--repo-path", str(tmp_path)])
    assert created.exit_code == 0
    config = tmp_path / ".spurhund-rules.yml"
    assert config.exists()

    added = runner.invoke(app, ["ignore", "add", "dist/**", "--config", str(config)])
    assert added.exit_code == 0
    listed = runner.invoke(app, ["ignore", "list", "--config", str(config)])
    assert listed.exit_code == 0
    assert "dist/**" in listed.output

    removed = runner.invoke(app, ["ignore", "remove", "dist/**", "--config", str(config)])
    assert removed.exit_code == 0

    missing = runner.invoke(app, ["ignore", "list", "--config", str(tmp_path / "missing.yml")])
    assert missing.exit_code == 2

    again = runner.invoke(app, ["init", "--repo-path", str(tmp_path)])
    assert again.exit_code == 0
    assert "already exists" in again.output.lower()

    duplicate = runner.invoke(app, ["ignore", "add", "dist/**", "--config", str(config)])
    runner.invoke(app, ["ignore", "add", "dist/**", "--config", str(config)])
    second = runner.invoke(app, ["ignore", "add", "dist/**", "--config", str(config)])
    assert second.exit_code == 0
    assert "already present" in second.output

    absent = runner.invoke(app, ["ignore", "remove", "not-there/**", "--config", str(config)])
    assert absent.exit_code == 0
    assert "not found" in absent.output

    no_config = runner.invoke(app, ["ignore", "add", "dist/**", "--config", str(tmp_path / "missing.yml")])
    assert no_config.exit_code == 2
    no_remove = runner.invoke(app, ["ignore", "remove", "dist/**", "--config", str(tmp_path / "missing.yml")])
    assert no_remove.exit_code == 2

    config.write_text("rules: [\n", encoding="utf-8")
    invalid_list = runner.invoke(app, ["ignore", "list", "--config", str(config)])
    assert invalid_list.exit_code == 2


def test_scan_failure_paths(tmp_path: Path, runner, monkeypatch):
    repo = tmp_path / "repo"
    init_repo(repo)
    (repo / "clean.py").write_text("print('hello')\n", encoding="utf-8")
    (repo / "blob.bin").write_bytes(b"abc\x00def")
    commit_all(repo, "base")

    not_dir = tmp_path / "file.txt"
    not_dir.write_text("x", encoding="utf-8")
    for command in ("scan-repo", "scan-staged", "scan-ci"):
        missing = runner.invoke(app, [command, str(tmp_path / "missing-root"), *_rules_args()])
        assert missing.exit_code == 2
        as_file = runner.invoke(app, [command, str(not_dir), *_rules_args()])
        assert as_file.exit_code == 2
        assert "not a directory" in as_file.output

    fresh = tmp_path / "fresh-rules.yml"
    created = runner.invoke(app, ["scan-repo", str(repo), "--config", str(fresh)])
    assert created.exit_code == 0
    assert fresh.exists()

    binary = runner.invoke(app, ["scan-repo", str(repo), *_rules_args()])
    assert binary.exit_code == 0

    (repo / "notes.png").write_text(LEAK_LINE + "\n", encoding="utf-8")
    git(repo, "add", "notes.png")
    ignored = runner.invoke(app, ["scan-staged", str(repo), *_rules_args()])
    assert ignored.exit_code == 0

    bad_rules = tmp_path / "bad-rules.yml"
    bad_rules.write_text(
        "version: '1.0'\nsettings:\n  ignore_paths: []\nrules:\n"
        "  - id: bad\n    name: Bad\n    regex_pattern: '('\n",
        encoding="utf-8",
    )
    broken_repo = runner.invoke(app, ["scan-repo", str(repo), "--config", str(bad_rules)])
    assert broken_repo.exit_code == 2
    broken_staged = runner.invoke(app, ["scan-staged", str(repo), "--config", str(bad_rules)])
    assert broken_staged.exit_code == 2

    missing_rules = runner.invoke(app, ["scan-file", str(repo / "clean.py"), "--config", str(tmp_path / "no-rules.yml")])
    assert missing_rules.exit_code == 2
    assert "Config file not found" in missing_rules.output

    def deny_config(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("spurhund.cli.load_config", deny_config)
    denied_config = runner.invoke(app, ["scan-file", str(repo / "clean.py"), *_rules_args()])
    assert denied_config.exit_code == 2
    assert "Permission denied reading config" in denied_config.output
    monkeypatch.undo()

    def unreadable_config(*args, **kwargs):
        raise OSError("busy")

    monkeypatch.setattr("spurhund.cli.load_config", unreadable_config)
    os_config = runner.invoke(app, ["scan-file", str(repo / "clean.py"), *_rules_args()])
    assert os_config.exit_code == 2
    assert "Unable to read config" in os_config.output


def test_scan_io_and_rule_errors(tmp_path: Path, runner, monkeypatch):
    repo = tmp_path / "repo"
    init_repo(repo)
    target = repo / "clean.py"
    target.write_text("print('hello')\n", encoding="utf-8")
    commit_all(repo, "base")

    def deny_read(self, *args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", deny_read)
    denied = runner.invoke(app, ["scan-file", str(target), *_rules_args()])
    assert denied.exit_code == 2
    assert "Permission denied" in denied.output
    monkeypatch.undo()

    def os_read(self, *args, **kwargs):
        raise OSError("busy")

    monkeypatch.setattr(Path, "read_text", os_read)
    unreadable = runner.invoke(app, ["scan-file", str(target), *_rules_args()])
    assert unreadable.exit_code == 2
    assert "Unable to read" in unreadable.output
    monkeypatch.undo()

    def explode(self, text, file_path="<stdin>"):
        raise RuntimeError("scan blew up")

    monkeypatch.setattr("spurhund.cli.ScannerEngine.scan_text", explode)
    failed = runner.invoke(app, ["scan-file", str(target), *_rules_args()])
    assert failed.exit_code == 2
    assert "Scan failed" in failed.output
    monkeypatch.undo()

    def deny_binary(path):
        raise PermissionError("denied")

    monkeypatch.setattr("spurhund.cli.is_binary_file", deny_binary)
    repo_denied = runner.invoke(app, ["scan-repo", str(repo), *_rules_args()])
    assert repo_denied.exit_code == 2
    assert "Permission denied" in repo_denied.output
    monkeypatch.undo()

    monkeypatch.setattr("spurhund.cli.is_binary_file", lambda path: False)

    def os_read_repo(self, *args, **kwargs):
        raise OSError("busy")

    monkeypatch.setattr(Path, "read_text", os_read_repo)
    repo_os = runner.invoke(app, ["scan-repo", str(repo), *_rules_args()])
    assert repo_os.exit_code == 2
    assert "Unable to read" in repo_os.output
    monkeypatch.undo()

    monkeypatch.setattr("spurhund.cli.is_binary_file", lambda path: False)
    monkeypatch.setattr("spurhund.cli.ScannerEngine.scan_text", explode)
    repo_scan = runner.invoke(app, ["scan-repo", str(repo), *_rules_args()])
    assert repo_scan.exit_code == 2
    assert "Scan failed" in repo_scan.output
    monkeypatch.undo()

    def bad_walk(self, pattern):
        raise OSError("walk")

    monkeypatch.setattr(Path, "rglob", bad_walk)
    walked = runner.invoke(app, ["scan-repo", str(repo), *_rules_args()])
    assert walked.exit_code == 2
    assert "Failed to walk" in walked.output
    monkeypatch.undo()

    target.write_text("print('changed')\n", encoding="utf-8")
    git(repo, "add", "clean.py")

    def bad_scan(self, text, file_path="<stdin>"):
        raise RuntimeError("line blew up")

    monkeypatch.setattr("spurhund.cli.ScannerEngine.scan_text", bad_scan)
    staged = runner.invoke(app, ["scan-staged", str(repo), *_rules_args()])
    assert staged.exit_code == 2
    assert "Scan failed" in staged.output
    monkeypatch.undo()

    monkeypatch.setattr("spurhund.cli.get_staged_diff", lambda root: (_ for _ in ()).throw(OSError("diff")))
    diff_error = runner.invoke(app, ["scan-staged", str(repo), *_rules_args()])
    assert diff_error.exit_code == 2
    assert "Git diff failed" in diff_error.output
    monkeypatch.undo()

    def fail_init(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("spurhund.cli.init_config", fail_init)
    init_failed = runner.invoke(app, ["init", "--repo-path", str(tmp_path / "fresh")])
    assert init_failed.exit_code == 2
    auto_init = runner.invoke(app, ["scan-repo", str(repo), "--config", str(tmp_path / "auto.yml")])
    assert auto_init.exit_code == 2
    assert "Failed to create config" in auto_init.output
    monkeypatch.undo()

    def fail_update(*args, **kwargs):
        raise OSError("locked")

    monkeypatch.setattr("spurhund.cli.update_ignore_path", fail_update)
    add_failed = runner.invoke(app, ["ignore", "add", "dist/**", "--config", str(RULES)])
    assert add_failed.exit_code == 2
    remove_failed = runner.invoke(app, ["ignore", "remove", "dist/**", "--config", str(RULES)])
    assert remove_failed.exit_code == 2

