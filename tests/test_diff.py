from pathlib import Path

import pytest

from spurhund.core.diff import _git_error_line, get_branch_diff, get_staged_diff, parse_patch_lines

from tests.support import LEAK_LINE, commit_all, git, init_repo


def test_git_error_line_keeps_the_first_diagnostic():
    assert _git_error_line("fatal: not a git repository\nusage: git", "fallback") == "not a git repository"
    assert _git_error_line("error: unknown option\nusage: git diff", "fallback") == "unknown option"
    assert _git_error_line("usage: git diff\nmore help", "fallback") == "fallback"
    assert _git_error_line("   \n", "fallback") == "fallback"


def test_parse_patch_lines_uses_hunk_line_numbers():
    patch = """diff --git a/dummy.py b/dummy.py
new file mode 100644
--- /dev/null
+++ b/dummy.py
@@ -0,0 +1,3 @@
+note = "ok"
+other = "ok"
+secret = "value"
diff --git a/old.py b/old.py
--- a/old.py
+++ /dev/null
@@ -1 +0,0 @@
-removed
Binary files a/pic.bin and b/pic.bin differ
diff --git "a/my file.py" "b/my file.py"
--- /dev/null
+++ "b/my file.py"
@@ -1,0 +8,2 @@
 context
+added
\\ No newline at end of file
diff --git a/plain.py b/plain.py
--- /dev/null
+++ plain.py
@@ -0,0 +1 @@
+plain
"""
    added = parse_patch_lines(patch)

    assert ("dummy.py", 3, 'secret = "value"') in added
    assert all(path != "old.py" for path, _, _ in added)
    assert ("my file.py", 9, "added") in added
    assert ("plain.py", 1, "plain") in added


def test_branch_diff_contains_only_branch_additions(tmp_path: Path):
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
    commit_all(repo, "add secret")

    added = parse_patch_lines(get_branch_diff("main", "HEAD", repo))
    files = {path for path, _, _ in added}

    assert "dummy.py" in files
    assert "base.py" not in files
    assert ("dummy.py", 3, LEAK_LINE) in added


def test_staged_diff_reads_the_index(tmp_path: Path):
    repo = tmp_path / "repo"
    init_repo(repo)
    (repo / "keep.py").write_text("print('base')\n", encoding="utf-8")
    commit_all(repo, "base")
    (repo / "staged.py").write_text(LEAK_LINE + "\n", encoding="utf-8")
    git(repo, "add", "staged.py")

    added = parse_patch_lines(get_staged_diff(repo))
    assert ("staged.py", 1, LEAK_LINE) in added


def test_git_diff_reports_a_missing_git_binary(tmp_path: Path, monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr("spurhund.core.diff.subprocess.run", missing)
    with pytest.raises(RuntimeError, match="not on PATH"):
        get_staged_diff(tmp_path)


def test_git_diff_reports_a_missing_binary_after_the_repo_check(tmp_path: Path, monkeypatch):
    calls = {"count": 0}

    def run(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return subprocess_result(0, "true\n", "")
        raise FileNotFoundError("git")

    monkeypatch.setattr("spurhund.core.diff.subprocess.run", run)
    with pytest.raises(RuntimeError, match="not on PATH"):
        get_branch_diff("main", "HEAD", tmp_path)


def subprocess_result(code: int, out: str, err: str):
    return type("Result", (), {"returncode": code, "stdout": out, "stderr": err})()
