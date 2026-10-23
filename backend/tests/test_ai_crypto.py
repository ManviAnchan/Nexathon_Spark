import sys
from pathlib import Path

# Ensure backend root is on sys.path for direct pytest invocation
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from unittest.mock import patch, MagicMock
import json
import subprocess
import pytest
import requests

from keynova.services.crypto.playground import (
    benchmark_algorithm,
    normalize_algorithm_name,
    SUPPORTED_ALGORITHMS
)
from keynova.services.remediation.engine import (
    generate_remediation,
    DISCLAIMER_WARNING,
    BaseLlmProvider,
    NullLlmProvider,
    OllamaLlmProvider,
    get_default_llm_provider
)

# Optional scanner imports if teammate scanner is merged
try:
    from keynova.services.scanner.python_ast import scan_python_file, AstCryptoFinding  # type: ignore
    from keynova.services.scanner.manifests import scan_manifest_file  # type: ignore
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False


# ==============================================================================
# Global Test Isolation: Enforce Deterministic Execution by Default
# ==============================================================================

@pytest.fixture(autouse=True)
def _ensure_deterministic_env(monkeypatch):
    """
    Ensure the test suite runs deterministically with NullLlmProvider by default,
    even if OLLAMA_ENABLED is set in the outer shell environment.
    Tests specifically targeting Ollama explicitly override this via monkeypatch
    or by passing a provider directly.
    """
    monkeypatch.setenv("OLLAMA_ENABLED", "false")


# ==============================================================================
# PQC Crypto Playground Tests
# ==============================================================================

def test_playground_supported_algorithms_live_execution():
    """Validates live benchmarking, microsecond timing, and byte lengths for all supported algorithms."""
    # 1. NIST FIPS 203 ML-KEM-768
    kem768 = benchmark_algorithm("ML-KEM-768", iterations=5)
    assert kem768["algorithm"] == "ML-KEM-768"
    assert "FIPS 203" in kem768["nist_standard"]
    assert kem768["public_key_bytes"] == 1184
    assert kem768["ciphertext_bytes"] == 1088
    assert kem768["security_level"] == 3
    assert kem768["avg_keygen_latency_us"] > 0
    assert kem768["avg_encap_latency_us"] > 0
    assert kem768["avg_decap_latency_us"] > 0

    # 2. NIST FIPS 203 ML-KEM-1024
    kem1024 = benchmark_algorithm("ML-KEM-1024", iterations=5)
    assert kem1024["algorithm"] == "ML-KEM-1024"
    assert kem1024["public_key_bytes"] == 1568
    assert kem1024["ciphertext_bytes"] == 1568
    assert kem1024["security_level"] == 5

    # 3. NIST FIPS 204 ML-DSA-65
    dsa65 = benchmark_algorithm("ML-DSA-65", iterations=5)
    assert dsa65["algorithm"] == "ML-DSA-65"
    assert "FIPS 204" in dsa65["nist_standard"]
    assert dsa65["public_key_bytes"] == 1952
    assert dsa65["ciphertext_bytes"] == 3309  # Signature payload size
    assert dsa65["security_level"] == 3

    # 4. Classical Baseline: RSA-2048
    rsa_res = benchmark_algorithm("RSA-2048", iterations=2)
    assert rsa_res["algorithm"] == "RSA-2048"
    assert rsa_res["public_key_bytes"] == 270
    assert rsa_res["ciphertext_bytes"] == 256
    assert rsa_res["security_level"] == 1
    assert rsa_res["avg_keygen_latency_us"] > 0

    # 5. Classical Baseline: ECDSA-P256
    ec_res = benchmark_algorithm("ECDSA-P256", iterations=5)
    assert ec_res["algorithm"] == "ECDSA-P256"
    assert ec_res["public_key_bytes"] == 65
    assert ec_res["ciphertext_bytes"] == 64
    assert ec_res["security_level"] == 1


def test_playground_alias_normalization():
    """Ensures algorithm aliases are properly normalized without errors."""
    assert normalize_algorithm_name("ml_kem_768") == "ML-KEM-768"
    assert normalize_algorithm_name("kyber-768") == "ML-KEM-768"
    assert normalize_algorithm_name("dilithium3") == "ML-DSA-65"
    assert normalize_algorithm_name("rsa2048") == "RSA-2048"
    assert normalize_algorithm_name("secp256r1") == "ECDSA-P256"


def test_playground_rejects_unknown_algorithm():
    """Ensures unknown or unsupported algorithms raise ValueError instead of silently defaulting."""
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        benchmark_algorithm("SUPER_QUANTUM_CIPHER_9000", iterations=10)

    with pytest.raises(ValueError, match="Unsupported algorithm"):
        benchmark_algorithm("DES", iterations=10)

    with pytest.raises(ValueError, match="Algorithm name must be a non-empty string"):
        benchmark_algorithm("", iterations=10)


def test_playground_iteration_validation():
    """Ensures iteration count is bounded strictly between 1 and 1000."""
    with pytest.raises(ValueError, match="iterations must be an integer"):
        benchmark_algorithm("ML-KEM-768", iterations=0)

    with pytest.raises(ValueError, match="iterations must be an integer"):
        benchmark_algorithm("ML-KEM-768", iterations=-5)

    with pytest.raises(ValueError, match="iterations must be an integer"):
        benchmark_algorithm("ML-KEM-768", iterations=50000)


# ==============================================================================
# AI Remediation Engine Tests (Deterministic Diff Engine)
# ==============================================================================

def test_remediation_rsa_kem_accuracy():
    """Validates RSA remediation recommends FIPS 203 ML-KEM with hybrid warnings."""
    finding = {
        "id": "find-rsa-01",
        "algorithm": "RSA",
        "file_path": "backend/crypto_service.py",
        "line_start": 9,
        "line_end": 12,
        "code_snippet": "self.private_key = legacy_rsa.generate_private_key(public_exponent=65537, key_size=2048)",
        "usage": "key_generation",
        "severity": "critical"
    }
    result = generate_remediation(finding)
    assert result["finding_id"] == "find-rsa-01"
    assert result["provider"] == "deterministic_fallback"
    assert "FIPS 203" in result["target_standard"]
    assert "ML-KEM-768" in result["target_standard"]
    assert "--- backend/crypto_service.py" in result["proposed_diff"]
    assert "+++ backend/crypto_service.py" in result["proposed_diff"]
    assert any("Key Encapsulation Mechanism (KEM)" in w for w in result["warnings"])
    assert any(DISCLAIMER_WARNING in w for w in result["warnings"])


def test_remediation_ecc_dsa_accuracy():
    """Validates ECC SECP256R1 remediation recommends FIPS 204 ML-DSA with payload warnings."""
    finding = {
        "id": "find-ecc-01",
        "algorithm": "ECC-SECP256R1",
        "file_path": "backend/auth.py",
        "line_start": 7,
        "line_end": 8,
        "code_snippet": "self.signing_key = ec.generate_private_key(ec.SECP256R1())",
        "usage": "token_signing",
        "severity": "high"
    }
    result = generate_remediation(finding)
    assert result["finding_id"] == "find-ecc-01"
    assert "FIPS 204" in result["target_standard"]
    assert "ML-DSA-65" in result["target_standard"]
    assert any("3309 bytes" in w for w in result["warnings"])
    assert any(DISCLAIMER_WARNING in w for w in result["warnings"])


def test_remediation_password_hash_memory_hardness():
    """Validates that password hashing recommends memory-hard scrypt/Argon2id and provides dual-verification migration."""
    finding = {
        "id": "find-pwd-01",
        "algorithm": "MD5",
        "file_path": "backend/hasher.py",
        "line_start": 9,
        "line_end": 9,
        "code_snippet": "return hashlib.md5(f'{salt}:{password}'.encode()).hexdigest()",
        "usage": "password_hashing",
        "severity": "low"
    }
    result = generate_remediation(finding)
    assert result["finding_id"] == "find-pwd-01"
    assert "Argon2id" in result["target_standard"] or "scrypt" in result["target_standard"]
    assert any("SHA-3 alone must NOT be used for password hashing" in w for w in result["warnings"])
    assert any("memory-hard" in w for w in result["warnings"])

    diff = result["proposed_diff"]
    assert "verify_and_migrate" in diff
    assert "scrypt" in diff
    assert "hmac.compare_digest" in diff
    assert "secrets.token_hex" in diff
    assert "legacy_hash" in diff


def test_remediation_general_hash_integrity():
    """Validates that general data integrity hashing recommends SHA-3-512."""
    finding = {
        "id": "find-hash-01",
        "algorithm": "MD5",
        "file_path": "backend/integrity.py",
        "line_start": 12,
        "line_end": 12,
        "code_snippet": "digest = hashlib.md5(payload).hexdigest()",
        "usage": "data_integrity",
        "severity": "low"
    }
    result = generate_remediation(finding)
    assert "FIPS 202 (SHA-3-512)" in result["target_standard"]


def test_remediation_manifest_dependency():
    """Validates dependency manifest remediation for legacy libraries."""
    finding = {
        "id": "find-manifest-01",
        "algorithm": "DES/RSA/RC4",
        "file_path": "requirements.txt",
        "line_start": 1,
        "line_end": 1,
        "code_snippet": "pycryptodome==3.10.1",
        "asset_type": "manifest",
        "library": "pycryptodome",
        "usage": "dependency",
        "severity": "low"
    }
    result = generate_remediation(finding)
    assert "Quantum-Agile" in result["target_standard"]
    assert "pqcrypto" in result["proposed_diff"]


def test_remediation_generic_unknown_algorithm():
    """Validates that uncataloged algorithms return a structured fallback diff with disclaimers."""
    finding = {
        "id": "find-custom-01",
        "algorithm": "GOST-R-34.10",
        "file_path": "src/legacy_crypto.py",
        "line_start": 40,
        "line_end": 40,
        "code_snippet": "key = gost.generate_key()",
        "usage": "custom_encryption",
        "severity": "medium"
    }
    result = generate_remediation(finding)
    assert result["finding_id"] == "find-custom-01"
    assert "Post-Quantum Cryptography" in result["target_standard"]
    assert "--- src/legacy_crypto.py" in result["proposed_diff"]
    assert any(DISCLAIMER_WARNING in w for w in result["warnings"])


def test_remediation_patches_apply_cleanly_to_vulnerable_suite():
    """
    Validates that deterministic remediation patches apply cleanly (via git apply --check)
    to their corresponding files in test-fixtures/vulnerable_payment_suite/.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent

    fixtures = [
        {
            "finding": {
                "id": "test-apply-rsa",
                "algorithm": "RSA",
                "file_path": "test-fixtures/vulnerable_payment_suite/backend/crypto_service.py",
                "asset_type": "source_code",
                "usage": "key_generation"
            },
            "path": repo_root / "test-fixtures/vulnerable_payment_suite/backend/crypto_service.py"
        },
        {
            "finding": {
                "id": "test-apply-ecc",
                "algorithm": "ECC-SECP256R1",
                "file_path": "test-fixtures/vulnerable_payment_suite/backend/auth.py",
                "asset_type": "source_code",
                "usage": "token_signing"
            },
            "path": repo_root / "test-fixtures/vulnerable_payment_suite/backend/auth.py"
        },
        {
            "finding": {
                "id": "test-apply-hasher",
                "algorithm": "MD5",
                "file_path": "test-fixtures/vulnerable_payment_suite/backend/hasher.py",
                "asset_type": "source_code",
                "usage": "password_hashing"
            },
            "path": repo_root / "test-fixtures/vulnerable_payment_suite/backend/hasher.py"
        },
        {
            "finding": {
                "id": "test-apply-manifest",
                "algorithm": "DES/RSA/RC4",
                "file_path": "test-fixtures/vulnerable_payment_suite/manifests/requirements.txt",
                "asset_type": "manifest",
                "library": "pycryptodome",
                "usage": "dependency"
            },
            "path": repo_root / "test-fixtures/vulnerable_payment_suite/manifests/requirements.txt"
        }
    ]

    for item in fixtures:
        assert item["path"].exists(), f"Fixture file not found: {item['path']}"
        rem = generate_remediation(item["finding"])
        diff_str = rem["proposed_diff"]
        assert diff_str and len(diff_str) > 0

        proc = subprocess.run(
            ["git", "apply", "--check", "-p0", "-"],
            input=diff_str,
            text=True,
            cwd=repo_root,
            capture_output=True
        )
        assert proc.returncode == 0, (
            f"Patch failed to apply cleanly to {item['finding']['file_path']}:\n"
            f"Return code: {proc.returncode}\n"
            f"Stderr: {proc.stderr}\n"
            f"Diff:\n{diff_str}"
        )


# ==============================================================================
# Local LLM Integration Tests (Ollama Mock Suite)
# ==============================================================================

SAMPLE_FINDING = {
    "id": "find-ollama-rsa",
    "algorithm": "RSA",
    "file_path": "backend/crypto_service.py",
    "line_start": 9,
    "line_end": 12,
    "code_snippet": "self.private_key = legacy_rsa.generate_private_key(public_exponent=65537, key_size=2048)",
    "usage": "key_generation",
    "severity": "critical",
    "asset_type": "source_code"
}

VALID_OLLAMA_BODY = {
    "target_standard": "FIPS 203 (ML-KEM-768)",
    "explanation": "Migrate 2048-bit RSA to NIST FIPS 203 ML-KEM-768 key encapsulation.",
    "proposed_diff": (
        "--- backend/crypto_service.py\n"
        "+++ backend/crypto_service.py\n"
        "@@ -9,4 +9,4 @@\n"
        "- self.private_key = legacy_rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "+ self.public_key, self.secret_key = ml_kem_768.keygen()\n"
    ),
    "warnings": [
        "ML-KEM is a Key Encapsulation Mechanism requiring hybrid symmetric encryption (e.g. AES-256-GCM).",
        DISCLAIMER_WARNING
    ],
    "migration_effort": "medium"
}

def test_ollama_provider_successful_response_mocked():
    """Validates successful local Ollama HTTP 200 JSON generation and provider tagging."""
    provider = OllamaLlmProvider(model="qwen2.5-coder:7b")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": json.dumps(VALID_OLLAMA_BODY)}

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = provider.generate_remediation(SAMPLE_FINDING)
        assert result is not None
        assert result["finding_id"] == "find-ollama-rsa"
        assert result["provider"] == "ollama/qwen2.5-coder:7b"
        assert result["target_standard"] == "FIPS 203 (ML-KEM-768)"
        assert "--- backend/crypto_service.py" in result["proposed_diff"]
        assert any(DISCLAIMER_WARNING in w for w in result["warnings"])

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "http://localhost:11434/api/generate"
        assert kwargs["json"]["model"] == "qwen2.5-coder:7b"
        assert kwargs["json"]["stream"] is False
        assert kwargs["json"]["format"] == "json"

    with patch("requests.post", return_value=mock_resp):
        dispatched = generate_remediation(SAMPLE_FINDING, provider=provider)
        assert dispatched["provider"] == "ollama/qwen2.5-coder:7b"


def test_ollama_provider_connection_refused_fallback():
    """Connection error in Ollama returns None and falls back to deterministic synthesis."""
    provider = OllamaLlmProvider()

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        res = provider.generate_remediation(SAMPLE_FINDING)
        assert res is None

        fallback = generate_remediation(SAMPLE_FINDING, provider=provider)
        assert fallback["provider"] == "deterministic_fallback"
        assert "FIPS 203" in fallback["target_standard"]
        assert fallback["finding_id"] == "find-ollama-rsa"


def test_ollama_provider_timeout_fallback():
    """Request timeout in Ollama returns None and falls back to deterministic synthesis."""
    provider = OllamaLlmProvider()

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Request timed out")):
        res = provider.generate_remediation(SAMPLE_FINDING)
        assert res is None

        fallback = generate_remediation(SAMPLE_FINDING, provider=provider)
        assert fallback["provider"] == "deterministic_fallback"


def test_ollama_provider_http_error_fallback():
    """HTTP 500 error in Ollama returns None and falls back to deterministic synthesis."""
    provider = OllamaLlmProvider()
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error in Ollama daemon"

    with patch("requests.post", return_value=mock_resp):
        res = provider.generate_remediation(SAMPLE_FINDING)
        assert res is None

        fallback = generate_remediation(SAMPLE_FINDING, provider=provider)
        assert fallback["provider"] == "deterministic_fallback"


def test_ollama_provider_malformed_json_fallback():
    """Malformed non-JSON output from Ollama returns None and falls back to deterministic synthesis."""
    provider = OllamaLlmProvider()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "This is raw text without any JSON structure."}

    with patch("requests.post", return_value=mock_resp):
        res = provider.generate_remediation(SAMPLE_FINDING)
        assert res is None

        fallback = generate_remediation(SAMPLE_FINDING, provider=provider)
        assert fallback["provider"] == "deterministic_fallback"


def test_ollama_provider_missing_fields_fallback():
    """Ollama output missing required fields returns None and falls back to deterministic synthesis."""
    provider = OllamaLlmProvider()
    bad_body = {
        "target_standard": "FIPS 203",
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": json.dumps(bad_body)}

    with patch("requests.post", return_value=mock_resp):
        res = provider.generate_remediation(SAMPLE_FINDING)
        assert res is None

        fallback = generate_remediation(SAMPLE_FINDING, provider=provider)
        assert fallback["provider"] == "deterministic_fallback"


def test_ollama_provider_invalid_diff_fallback():
    """Ollama output with invalid diff syntax (missing unified diff headers) returns None and falls back."""
    provider = OllamaLlmProvider()
    bad_diff_body = {
        **VALID_OLLAMA_BODY,
        "proposed_diff": "replace private_key with kyber_key in file"
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": json.dumps(bad_diff_body)}

    with patch("requests.post", return_value=mock_resp):
        res = provider.generate_remediation(SAMPLE_FINDING)
        assert res is None

        fallback = generate_remediation(SAMPLE_FINDING, provider=provider)
        assert fallback["provider"] == "deterministic_fallback"


def test_ollama_provider_appends_missing_disclaimer():
    """Ollama output lacking human-review disclaimer has it automatically appended."""
    provider = OllamaLlmProvider()
    body_no_disclaimer = {
        **VALID_OLLAMA_BODY,
        "warnings": ["Custom warning about key lengths"]
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": json.dumps(body_no_disclaimer)}

    with patch("requests.post", return_value=mock_resp):
        res = provider.generate_remediation(SAMPLE_FINDING)
        assert res is not None
        assert any(DISCLAIMER_WARNING in w for w in res["warnings"])


def test_ollama_provider_env_configuration(monkeypatch):
    """Verifies configurable environment variables for host, model, and timeout."""
    monkeypatch.setenv("OLLAMA_HOST", "http://192.168.1.100:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:14b")
    monkeypatch.setenv("OLLAMA_TIMEOUT", "45.0")

    provider = OllamaLlmProvider()
    assert provider.base_url == "http://192.168.1.100:11434"
    assert provider.model == "qwen2.5-coder:14b"
    assert provider.timeout == 45.0


def test_ollama_enabled_environment_toggle(monkeypatch):
    """Verifies OLLAMA_ENABLED environment variable controls default provider dispatch."""
    monkeypatch.setenv("OLLAMA_ENABLED", "false")
    prov_disabled = get_default_llm_provider()
    assert isinstance(prov_disabled, NullLlmProvider)

    monkeypatch.setenv("OLLAMA_ENABLED", "true")
    prov_enabled = get_default_llm_provider()
    assert isinstance(prov_enabled, OllamaLlmProvider)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": json.dumps(VALID_OLLAMA_BODY)}
    with patch("requests.post", return_value=mock_resp):
        res = generate_remediation(SAMPLE_FINDING)
        assert res["provider"] == "ollama/qwen2.5-coder:7b"


def test_ollama_rejects_rsa_model_proposing_classical_ecc():
    """
    Ollama response claiming FIPS 203 / ML-KEM but proposing classical ECC (SECP256R1, ECDH)
    or invalid public_key.encrypt() must be rejected and trigger deterministic fallback.
    """
    provider = OllamaLlmProvider()
    bad_rsa_body = {
        "target_standard": "FIPS 203 (ML-KEM-768)",
        "explanation": "Migrate RSA to post-quantum cryptography using elliptic curves.",
        "proposed_diff": (
            "--- backend/crypto_service.py\n"
            "+++ backend/crypto_service.py\n"
            "@@ -9,4 +9,4 @@\n"
            "- self.private_key = legacy_rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            "+ self.private_key = ec.generate_private_key(ec.SECP256R1())\n"
            "+ self.encrypted = self.public_key.encrypt(data)\n"
        ),
        "warnings": [DISCLAIMER_WARNING],
        "migration_effort": "medium"
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": json.dumps(bad_rsa_body)}

    with patch("requests.post", return_value=mock_resp):
        res = provider.generate_remediation(SAMPLE_FINDING)
        assert res is None

        fallback = generate_remediation(SAMPLE_FINDING, provider=provider)
        assert fallback["provider"] == "deterministic_fallback"
        assert "FIPS 203" in fallback["target_standard"]
        assert "SECP256R1" not in fallback["proposed_diff"]
        assert "ml_kem_768" in fallback["proposed_diff"]


def test_ollama_rejects_ecc_signing_proposing_classical_ecdsa():
    """
    Ollama response claiming FIPS 204 / ML-DSA for an ECC signature finding but proposing
    classical ECDSA / SECP256R1 / ec.ECDSA must be rejected and trigger deterministic fallback.
    """
    ecc_finding = {
        "id": "find-ecc-auth",
        "algorithm": "ECC-SECP256R1",
        "file_path": "backend/auth.py",
        "line_start": 7,
        "line_end": 10,
        "code_snippet": "self.signing_key = ec.generate_private_key(ec.SECP256R1())",
        "usage": "token_signing",
        "severity": "high",
        "asset_type": "source_code"
    }
    provider = OllamaLlmProvider()
    bad_ecc_body = {
        "target_standard": "FIPS 204 (ML-DSA-65)",
        "explanation": "Migrate to modern signature scheme.",
        "proposed_diff": (
            "--- backend/auth.py\n"
            "+++ backend/auth.py\n"
            "@@ -7,3 +7,3 @@\n"
            "- self.signing_key = ec.generate_private_key(ec.SECP256R1())\n"
            "+ self.signing_key = ec.generate_private_key(ec.SECP384R1())\n"
            "+ signature = self.signing_key.sign(data, ec.ECDSA(hashes.SHA384()))\n"
        ),
        "warnings": [DISCLAIMER_WARNING],
        "migration_effort": "medium"
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": json.dumps(bad_ecc_body)}

    with patch("requests.post", return_value=mock_resp):
        res = provider.generate_remediation(ecc_finding)
        assert res is None

        fallback = generate_remediation(ecc_finding, provider=provider)
        assert fallback["provider"] == "deterministic_fallback"
        assert "FIPS 204" in fallback["target_standard"]
        assert "ml_dsa_65" in fallback["proposed_diff"]


def test_ollama_rejects_password_hash_proposing_fast_hash():
    """
    Ollama response for password hashing proposing fast hashes (SHA-256, SHA-3, MD5)
    without memory-hard KDF must be rejected and trigger deterministic fallback.
    """
    pwd_finding = {
        "id": "find-pwd-md5",
        "algorithm": "MD5",
        "file_path": "backend/hasher.py",
        "line_start": 9,
        "line_end": 10,
        "code_snippet": "return hashlib.md5(password.encode()).hexdigest()",
        "usage": "password_hashing",
        "severity": "low",
        "asset_type": "source_code"
    }
    provider = OllamaLlmProvider()
    bad_pwd_body = {
        "target_standard": "FIPS 202 (SHA-3-512)",
        "explanation": "Upgrade password hash to modern SHA-3-512.",
        "proposed_diff": (
            "--- backend/hasher.py\n"
            "+++ backend/hasher.py\n"
            "@@ -9,2 +9,2 @@\n"
            "- return hashlib.md5(password.encode()).hexdigest()\n"
            "+ return hashlib.sha3_512(password.encode()).hexdigest()\n"
        ),
        "warnings": [DISCLAIMER_WARNING],
        "migration_effort": "low"
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": json.dumps(bad_pwd_body)}

    with patch("requests.post", return_value=mock_resp):
        res = provider.generate_remediation(pwd_finding)
        assert res is None

        fallback = generate_remediation(pwd_finding, provider=provider)
        assert fallback["provider"] == "deterministic_fallback"
        assert "scrypt" in fallback["target_standard"] or "Argon2id" in fallback["target_standard"]
        assert "sha3_512" not in fallback["proposed_diff"]


@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="Scanner modules not yet merged from backend core lead")
def test_e2e_scanner_to_remediation_pipeline():
    """
    End-to-end integration test scanning real test fixture files with AST and manifest
    scanners, mapping real findings, and verifying diff and warning synthesis.
    """
    fixture_dir = Path(__file__).resolve().parent.parent.parent / "test-fixtures" / "vulnerable_payment_suite"
    assert fixture_dir.exists(), f"Vulnerable payment suite fixture not found at {fixture_dir}"

    py_findings: list[AstCryptoFinding] = []
    for py_file in sorted(fixture_dir.rglob("*.py")):
        py_findings.extend(scan_python_file(py_file, relative_to=fixture_dir))

    manifest_findings: list[dict] = []
    for manifest_file in sorted(fixture_dir.rglob("*")):
        if manifest_file.name.lower() in ["requirements.txt", "package.json"]:
            manifest_findings.extend(scan_manifest_file(manifest_file, relative_to=fixture_dir))

    assert len(py_findings) == 3, f"Expected 3 AST findings, found {len(py_findings)}"
    assert len(manifest_findings) == 1, f"Expected 1 manifest finding, found {len(manifest_findings)}"

    with pytest.raises(AttributeError, match="'AstCryptoFinding' object has no attribute 'get'"):
        generate_remediation(py_findings[0])

    all_findings_mapped = [f.to_dict() for f in py_findings] + manifest_findings

    remediation_by_alg = {}
    for finding in all_findings_mapped:
        rem = generate_remediation(finding)
        assert rem["provider"] == "deterministic_fallback"
        assert len(rem["proposed_diff"]) > 0
        remediation_by_alg[rem["algorithm"]] = rem

    # Verify algorithmic mappings
    assert "FIPS 204" in remediation_by_alg["ECC-SECP256R1"]["target_standard"]
    assert "FIPS 203" in remediation_by_alg["RSA"]["target_standard"]
    assert "RFC 9106" in remediation_by_alg["MD5"]["target_standard"] or "scrypt" in remediation_by_alg["MD5"]["target_standard"]
    assert "Quantum-Agile" in remediation_by_alg["DES/RSA/RC4"]["target_standard"]
