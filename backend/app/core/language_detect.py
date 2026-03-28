from pathlib import Path
from collections import Counter


def detect_language(repo_path: str) -> str:
    """Detect primary language in a repo by file extension count."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
        ".php": "php",
    }
    counts: Counter = Counter()
    for f in Path(repo_path).rglob("*"):
        if f.suffix in ext_map:
            counts[ext_map[f.suffix]] += 1
    if not counts:
        return "unknown"
    return counts.most_common(1)[0][0]
