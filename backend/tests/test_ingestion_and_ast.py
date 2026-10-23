import pytest
import io
import zipfile
from pathlib import Path
from keynova.services.ingestion.git import validate_git_url, GitSecurityViolation
from keynova.services.ingestion.zip import safe_extract_zip, ZipSlipSecurityError
from keynova.services.scanner.python_ast import scan_python_file

try:
    from keynova.services.intelligence.scoring import calculate_readiness_score
except ImportError:
    from keynova.services.scanner.orchestrator import calculate_readiness_score

def test_git_url_security_validation():
    # Enforces HTTPS
    with pytest.raises(GitSecurityViolation):
        validate_git_url("git@github.com:org/repo.git")

    with pytest.raises(GitSecurityViolation):
        validate_git_url("http://insecure-site.com/repo.git")

    with pytest.raises(GitSecurityViolation):
        validate_git_url("file:///etc/passwd")

    with pytest.raises(GitSecurityViolation):
        validate_git_url("https://github.com/org/repo.git; rm -rf /")

    # Valid HTTPS should pass
    validate_git_url("https://github.com/keynova/sample-repo.git")

def test_zip_slip_rejection(tmp_path):
    # Construct malicious zip with ../ path
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("../../evil.txt", "malicious payload")
    
    zip_file = tmp_path / "malicious.zip"
    zip_file.write_bytes(zip_buffer.getvalue())

    target_dir = tmp_path / "extracted"
    with pytest.raises(ZipSlipSecurityError):
        safe_extract_zip(zip_file, target_dir)

def test_ast_python_scanner(tmp_path):
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa as my_rsa
# Comment saying do not use rsa
key = my_rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""
    py_file = tmp_path / "service.py"
    py_file.write_text(code, encoding="utf-8")

    findings = scan_python_file(py_file, relative_to=tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.algorithm == "RSA"
    assert f.key_size == 2048
    assert f.severity == "critical"
    assert f.hndl is True
    assert f.line_start == 4

def test_deterministic_scoring():
    findings = [
        {"severity": "critical", "hndl": True, "confidence": 0.95},
        {"severity": "low", "hndl": False, "confidence": 1.0}
    ]
    report = calculate_readiness_score(findings, total_files=10, scanned_files=10)
    assert 0 <= report["readiness_score"] <= 100
    assert report["coverage_percent"] == 100.0
    assert report["hndl_count"] == 1
