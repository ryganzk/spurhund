import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / ".spurhund-rules.yml"
LEAK_LINE = 'test_key = "dGVzdF9zZWNyZXRfa2V5X2Zvcl90ZXN0aW5nXzEyMzQ="' # spurhund:ignore


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-b", "main", str(repo)],
        check=True,
        capture_output=True,
        text=True,
    )


def commit_all(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(
        repo,
        "-c",
        "user.email=spurhund-tests@example.com",
        "-c",
        "user.name=Spurhund Tests",
        "commit",
        "-m",
        message,
    )
