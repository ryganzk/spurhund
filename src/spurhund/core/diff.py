import re
import subprocess
from pathlib import Path

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def get_staged_diff(repo_path: str | Path = ".") -> str:
    """Return the staged unified diff for a git repository."""
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_path),
                "diff",
                "--cached",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git is not installed or not on PATH") from exc

    if result.returncode != 0:
        message = result.stderr.strip() or "git diff --cached failed"
        raise RuntimeError(message)
    return result.stdout


def parse_patch_lines(patch: str) -> list[tuple[str, int, str]]:
    """Extract added lines from a unified diff.

    Returns (file_path, line_number, text) for each line introduced in the new file.
    """
    added: list[tuple[str, int, str]] = []
    current_file: str | None = None
    new_line = 0
    in_hunk = False

    for raw in patch.splitlines():
        if raw.startswith("diff --git ") or raw.startswith("Binary files ") or raw.startswith("GIT binary patch"):
            current_file = None
            in_hunk = False
            continue

        if not in_hunk and raw.startswith("+++ "):
            current_file = _parse_diff_path(raw[4:])
            continue

        header = _HUNK_HEADER.match(raw)
        if header:
            in_hunk = True
            new_line = int(header.group(1))
            continue

        if not in_hunk or current_file is None:
            continue

        if raw.startswith("+"):
            added.append((current_file, new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue
        else:
            new_line += 1

    return added


def _parse_diff_path(path: str) -> str | None:
    """Normalize the path from a '+++ b/...' header. None means the file was deleted."""
    path = path.split("\t", 1)[0].strip()
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        path = path[1:-1].encode("utf-8", "backslashreplace").decode("unicode_escape")
    if path == "/dev/null":
        return None
    if path.startswith("b/") or path.startswith("a/"):
        path = path[2:]
    return path
