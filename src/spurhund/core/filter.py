from pathlib import Path
from fnmatch import fnmatch
from typing import List

def is_binary_file(file_path: Path) -> bool:
    """Checks the first 8192 bytes for null bytes to identify binaries."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(8192)
            return b"\x00" in chunk
    except (OSError, PermissionError):
        return True

def should_ignore_path(rel_path: str, ignore_patterns: List[str]) -> bool:
    """Evaluates whether a relative path matches any glob ignore pattern."""
    # Standardize POSIX separators for cross-platform globbing
    normalized = rel_path.replace("\\", "/")
    for pattern in ignore_patterns:
        # Match direct path, glob pattern, or directory prefix
        if fnmatch(normalized, pattern) or fnmatch(normalized.split("/")[-1], pattern):
            return True
        if pattern.endswith("/**") and normalized.startswith(pattern[:-3]):
            return True
    return False