from pathlib import Path
from typing import List, Tuple, Set
import yaml
from spurhund.models import Rule

DEFAULT_CONFIG_TEMPLATE = {
    "version": "1.0",
    "settings": {
        "ignore_paths": [
            ".git/**",
            ".venv/**",
            "node_modules/**",
            "vendor/**",
            "*.lock",
            "*.png",
            "*.jpg",
            "*.pdf",
            "*.pyc",
        ]
    },
    "rules": [
        {
            "id": "sec-github-pat",
            "name": "GitHub Personal Access Token",
            "severity": "CRITICAL",
            "prefixes": ["ghp_", "github_pat_"],
            "regex_pattern": r"(?i)(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
            "min_entropy": 3.0,
            "capture_group": 0,
            "path_excludes": ["**/tests/fixtures/**"],
        },
        {
            "id": "sec-generic-key",
            "name": "Generic High-Entropy API Secret",
            "severity": "HIGH",
            "prefixes": ["key", "token", "secret", "auth", "cred"],
            "regex_pattern": r"""(?i)(?:[a-z0-9_]*(?:key|secret|token|auth|cred)[a-z0-9_]*)\s*[:=]\s*["']([a-zA-Z0-9_\-\+/=]{24,64})["']""",
            "capture_group": 1,
            "min_entropy": 3.8,
            "exclude_values": ["(?i)mock", "(?i)dummy", "(?i)placeholder"],
            "path_excludes": ["**/*_test.py", "**/test_*.py"],
        },
    ],
}

def parse_gitignore(gitignore_path: Path) -> List[str]:
    """Reads .gitignore and normalizes entries to glob patterns."""
    if not gitignore_path.exists():
        return []

    patterns: List[str] = []
    with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue

            # Strip leading slashes for relative path resolution
            if clean.startswith("/"):
                clean = clean[1:]

            # Directory rule normalization
            if clean.endswith("/"):
                patterns.append(f"{clean}**")
                patterns.append(clean[:-1])
            else:
                patterns.append(clean)
                patterns.append(f"{clean}/**")

    return patterns

def load_raw_config(config_path: Path) -> dict:
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found at {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def save_raw_config(config_path: Path, data: dict) -> None:
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False, indent=2)

def load_config(config_path: Path = Path(".spurhund-rules.yml")) -> Tuple[List[str], List[Rule]]:
    """Loads universal path ignores and Rule models from YAML."""
    data = load_raw_config(config_path)

    global_ignores = data.get("settings", {}).get("ignore_paths", [])

    rules: List[Rule] = []
    for r in data.get("rules", []):
        rules.append(Rule(
            id=r["id"],
            name=r["name"],
            severity=r.get("severity", "HIGH"),
            prefixes=r.get("prefixes", []),
            regex_pattern=r["regex_pattern"],
            min_entropy=float(r.get("min_entropy", 0.0)),
            capture_group=int(r.get("capture_group", 0)),
            exclude_values=r.get("exclude_values", []),
            path_excludes=r.get("path_excludes", [])
        ))

    return global_ignores, rules

def init_config(repo_root: Path, config_path: Path) -> Tuple[bool, int]:
    """Creates config if missing, merges .gitignore, returns (created_new, gitignore_count)."""
    created = False
    if not config_path.exists():
        data = DEFAULT_CONFIG_TEMPLATE.copy()
        created = True
    else:
        data = load_raw_config(config_path)

    settings = data.setdefault("settings", {})
    existing_ignores: List[str] = settings.setdefault("ignore_paths", [])

    gitignore_patterns = parse_gitignore(repo_root / ".gitignore")
    
    # Idempotent union preserving ordering
    seen = set(existing_ignores)
    added_count = 0
    for pat in gitignore_patterns:
        if pat not in seen:
            existing_ignores.append(pat)
            seen.add(pat)
            added_count += 1

    save_raw_config(config_path, data)
    return created, added_count

def update_ignore_path(config_path: Path, pattern: str, action: str) -> bool:
    """Idempotently adds or removes a path pattern from settings.ignore_paths."""
    data = load_raw_config(config_path)
    settings = data.setdefault("settings", {})
    existing: List[str] = settings.setdefault("ignore_paths", [])

    changed = False
    if action == "add":
        if pattern not in existing:
            existing.append(pattern)
            changed = True
    elif action == "remove":
        if pattern in existing:
            existing.remove(pattern)
            changed = True

    if changed:
        save_raw_config(config_path, data)
    return changed