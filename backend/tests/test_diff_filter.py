import pytest
from pathlib import Path

from keynova.services.scanner.diff_filter import (
    is_crypto_relevant_file,
    filter_crypto_affected_files,
    get_git_changed_files,
    IGNORED_EXTENSIONS
)


class TestDiffFilterClassification:
    """Tests selective cryptographic change detection on individual files."""

    def test_ignored_asset_extensions(self, tmp_path):
        for ext in [".md", ".css", ".html", ".svg", ".png", ".jpg", ".pdf"]:
            sample = tmp_path / f"test{ext}"
            sample.write_text("import cryptography\nhashlib.sha256()", encoding="utf-8")
            assert is_crypto_relevant_file(sample) is False, f"Extension {ext} should be ignored"

    def test_dependency_manifests_always_relevant(self, tmp_path):
        reqs = tmp_path / "requirements.txt"
        reqs.write_text("fastapi==0.110.0\nuvicorn==0.28.0", encoding="utf-8")
        assert is_crypto_relevant_file(reqs) is True

        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies": {"react": "^18.0.0"}}', encoding="utf-8")
        assert is_crypto_relevant_file(pkg) is True

    def test_non_crypto_python_code_ignored(self, tmp_path):
        model_file = tmp_path / "models.py"
        model_file.write_text(
            """
class User:
    def __init__(self, name: str, age: int):
        self.name = name
        self.age = age

def calculate_tax(subtotal: float, rate: float = 0.08) -> float:
    return subtotal * rate
""",
            encoding="utf-8"
        )
        assert is_crypto_relevant_file(model_file) is False

    def test_crypto_python_code_detected(self, tmp_path):
        crypto_snippets = [
            ("rsa_gen.py", "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key()"),
            ("ecc_auth.py", "from cryptography.hazmat.primitives.asymmetric import ec\nec.SECP256R1()"),
            ("hash_util.py", "import hashlib\nhashlib.md5(b'test')"),
            ("pqc_kem.py", "import pqcrypto.kem.kyber512 as kyber\nkyber.generate_keypair()"),
            ("cipher_enc.py", "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_EAX)"),
            ("secrets_tok.py", "import secrets\ntok = secrets.token_hex(16)"),
            ("hmac_sign.py", "import hmac\nhmac.new(key, msg, 'sha256')"),
        ]

        for filename, content in crypto_snippets:
            f = tmp_path / filename
            f.write_text(content, encoding="utf-8")
            assert is_crypto_relevant_file(f) is True, f"Failed to detect crypto surface in {filename}"


class TestFilterCryptoAffectedFiles:
    """Tests batch filtering across changed files."""

    def test_filter_crypto_affected_files_mixed_commit(self, tmp_path):
        # Create non-crypto assets
        readme = tmp_path / "README.md"
        readme.write_text("# Project Documentation", encoding="utf-8")

        style = tmp_path / "styles.css"
        style.write_text("body { color: #fff; }", encoding="utf-8")

        db_model = tmp_path / "db.py"
        db_model.write_text("def connect(): return None", encoding="utf-8")

        # Create crypto assets
        crypto_svc = tmp_path / "crypto_service.py"
        crypto_svc.write_text("import hashlib\nhashlib.sha1(b'x')", encoding="utf-8")

        reqs = tmp_path / "requirements.txt"
        reqs.write_text("pycryptodome==3.10.1", encoding="utf-8")

        changed = [
            "README.md",
            "styles.css",
            "db.py",
            "crypto_service.py",
            "requirements.txt",
            "nonexistent_file.py"
        ]

        affected = filter_crypto_affected_files(changed, base_dir=tmp_path)
        affected_names = {p.name for p in affected}

        assert affected_names == {"crypto_service.py", "requirements.txt"}
        assert len(affected) == 2

    def test_filter_crypto_affected_files_zero_crypto_change(self, tmp_path):
        doc = tmp_path / "architecture.md"
        doc.write_text("Design document", encoding="utf-8")

        helper = tmp_path / "string_utils.py"
        helper.write_text("def slugify(s): return s.lower().strip()", encoding="utf-8")

        changed = ["architecture.md", "string_utils.py"]
        affected = filter_crypto_affected_files(changed, base_dir=tmp_path)
        assert len(affected) == 0, "Non-crypto commit should result in zero affected crypto files"

    def test_git_diff_fallback_safe(self, tmp_path):
        # When git diff fails or runs in non-git directory, returns safe fallback
        non_git_dir = tmp_path / "non_git_workspace"
        non_git_dir.mkdir()
        file1 = non_git_dir / "test.py"
        file1.write_text("print('hello')", encoding="utf-8")

        changed = get_git_changed_files(non_git_dir)
        assert len(changed) >= 1
        assert file1 in changed
