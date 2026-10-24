import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Set, Union, Sequence

# Non-code or purely presentation assets to ignore
IGNORED_EXTENSIONS = {
    ".md", ".txt", ".rst", ".css", ".scss", ".less", ".html", ".svg",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".lock", ".map"
}

# Relevant code/manifest extensions
ALLOWED_EXTENSIONS = {".py", ".json"}

# Cryptographic libraries, module references, and primitive keywords
CRYPTO_SURFACE_PATTERNS = [
    r"\bcryptography\b",
    r"\bCrypto\b",
    r"\bhashlib\b",
    r"\bpqcrypto\b",
    r"\bsecrets\b",
    r"\bhmac\b",
    r"\brsa\b",
    r"\becc?\b",
    r"\bsecp256r1\b",
    r"\bgenerate_private_key\b",
    r"\bml[-_]kem\b",
    r"\bml[-_]dsa\b",
    r"\bkyber\b",
    r"\bdilithium\b",
    r"\bmd5\b",
    r"\bsha1\b",
    r"\btripledes\b",
    r"\bblowfish\b",
    r"\bpycryptodome\b",
    r"\bciphers?\b",
    r"\baes\b"
]
CRYPTO_REGEX = re.compile("|".join(CRYPTO_SURFACE_PATTERNS), re.IGNORECASE)

def is_crypto_relevant_file(file_path: Path) -> bool:
    """
    Determines if a modified file contains cryptographic symbols or imports.
    Returns False for non-code files or files with zero cryptographic surface.
    """
    name = file_path.name.lower()
    # Dependency manifests are always relevant
    if name in ["requirements.txt", "package.json"]:
        return True

    if file_path.suffix.lower() in IGNORED_EXTENSIONS:
        return False

    if file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
        return False

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        return bool(CRYPTO_REGEX.search(content))
    except Exception:
        return False

def filter_crypto_affected_files(
    changed_files: Sequence[Union[str, Path]],
    base_dir: Path
) -> List[Path]:
    """
    Filters a list of changed files down to only those that affect cryptographic posture.
    Skips non-code files and files lacking any cryptographic imports or invocations.
    """
    affected: List[Path] = []
    for f in changed_files:
        full_path = Path(f) if Path(f).is_absolute() else base_dir / f
        if not full_path.exists() or not full_path.is_file():
            continue

        if is_crypto_relevant_file(full_path):
            affected.append(full_path)

    return affected

def get_git_changed_files(repo_path: Path, baseline_ref: Optional[str] = None) -> List[Path]:
    """
    Retrieves the list of changed files from git diff.
    If baseline_ref is provided, runs `git diff --name-only baseline_ref HEAD`.
    Otherwise, inspects unstaged + staged working tree changes.
    """
    try:
        if baseline_ref:
            cmd = ["git", "diff", "--name-only", baseline_ref, "HEAD"]
        else:
            cmd = ["git", "diff", "--name-only", "HEAD"]

        result = subprocess.run(
            cmd,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            check=True
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return [repo_path / line for line in lines]
    except Exception:
        # Fallback: return all files in repository if git diff fails
        return [p for p in repo_path.rglob("*") if p.is_file()]
