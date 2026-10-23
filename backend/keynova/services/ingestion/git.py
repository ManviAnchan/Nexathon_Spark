import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

MAX_REPO_SIZE_MB = 100
CLONE_TIMEOUT_SECONDS = 30

class GitSecurityViolation(Exception):
    pass

class GitCloneError(Exception):
    pass

def validate_git_url(url: str) -> None:
    """Enforces HTTPS protocol and blocks file://, ssh://, git@ protocols."""
    clean_url = url.strip()
    if clean_url.startswith("git@") or "ssh://" in clean_url or clean_url.startswith("file://"):
        raise GitSecurityViolation("Security Violation: Only secure HTTPS Git URLs are permitted.")

    if not clean_url.startswith("https://"):
        raise GitSecurityViolation("Invalid Git URL: URL must begin with https://")

    # Basic regex sanitization to prevent flag injection
    if re.search(r"[\s;&|`$]", clean_url):
        raise GitSecurityViolation("Invalid Git URL: Contains illegal characters or command separators.")

def clone_git_repository(
    url: str,
    target_dir: Path,
    branch: Optional[str] = None
) -> Path:
    """
    Shallow clones a remote Git repository with timeout, depth 1, and size bounds.
    """
    validate_git_url(url)

    target_dir = target_dir.resolve()
    if target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)
    target_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([url, str(target_dir)])

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS
        )
        if proc.returncode != 0:
            raise GitCloneError(f"Git clone failed: {proc.stderr.strip()}")
    except subprocess.TimeoutExpired:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise GitCloneError(f"Git clone timed out after {CLONE_TIMEOUT_SECONDS} seconds.")
    except Exception as e:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise GitCloneError(f"Failed to clone repository: {e}")

    # Enforce directory size bounds
    total_size = sum(f.stat().st_size for f in target_dir.rglob('*') if f.is_file())
    if total_size > MAX_REPO_SIZE_MB * 1024 * 1024:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise GitSecurityViolation(f"Cloned repository exceeds maximum size limit of {MAX_REPO_SIZE_MB}MB.")

    return target_dir
