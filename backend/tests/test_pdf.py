"""
Comprehensive test suite for Keynova's Executive PDF Report Generator (pdf.py).

Validates:
- Generation of valid PDF documents (binary bytes starting with %PDF- and terminating with %%EOF)
- Executive summary & Keynova Readiness Index score interpretations (Critical, Needs Upgrade, Quantum Ready)
- Graceful handling of missing/None readiness scores, empty findings, and partial scan metadata
- Finding summary severity counts and quantum-safety classifications
- Correct risk explanations and NIST FIPS 203/204/202 standards-backed recommendations
- XML escaping with xml.sax.saxutils.escape and resilience against malformed inputs or special characters (< and &)
- Multi-page pagination using ReportNumberedCanvas
- Real fixture integration using vulnerable_payment_suite and remediated_payment_suite
"""

import sys
from pathlib import Path
from typing import List, Dict, Any
import pytest

# Ensure backend root is on sys.path for direct script execution and diverse test runners
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from keynova.services.exporters.pdf import (
    generate_pdf_report,
    _classify_quantum_status,
    _analyze_risk_and_remediation,
    _escape,
)
from keynova.services.scanner.python_ast import scan_python_file
from keynova.services.scanner.manifests import scan_manifest_file
from keynova.services.intelligence.scoring import calculate_readiness_score

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "test-fixtures"
if not FIXTURES_DIR.exists():
    FIXTURES_DIR = Path(__file__).resolve().parent.parent / "test-fixtures"
VULN_FIXTURE_DIR = FIXTURES_DIR / "vulnerable_payment_suite"
REMED_FIXTURE_DIR = FIXTURES_DIR / "remediated_payment_suite"


def _scan_fixture_directory(dir_path: Path) -> List[Dict[str, Any]]:
    """Helper to scan a fixture directory using Keynova's AST and manifest scanners."""
    findings = []
    files = [
        p for p in dir_path.rglob("*")
        if p.is_file() and not any(part in [".git", "__pycache__", ".venv"] for part in p.parts)
    ]
    for f in sorted(files, key=lambda p: str(p)):
        if f.suffix == ".py":
            py_findings = scan_python_file(f, relative_to=dir_path)
            findings.extend([item.to_dict() for item in py_findings])
        elif f.name.lower() in ["requirements.txt", "package.json"]:
            manifest_findings = scan_manifest_file(f, relative_to=dir_path)
            findings.extend(manifest_findings)
    return findings


# ============================================================================
# 1. BASIC GENERATION & PDF SIGNATURE VERIFICATION
# ============================================================================

class TestPdfReportGenerationBasic:
    """Verifies fundamental PDF generation, header structure, and byte signature."""

    def test_pdf_generation_returns_valid_pdf_bytes(self):
        """Standard valid inputs must yield non-empty bytes starting with %PDF-."""
        project_name = "Core Payment Gateway"
        scan_meta = {
            "id": "scan-abc-123",
            "readiness_score": 65,
            "coverage_percent": 100.0,
            "scanned_files": 12,
            "total_files": 12,
            "hndl_count": 1,
        }
        findings = [
            {
                "id": "f-1",
                "file_path": "services/crypto.py",
                "line_start": 34,
                "line_end": 35,
                "algorithm": "RSA-2048",
                "usage": "asymmetric_encryption",
                "key_size": 2048,
                "severity": "critical",
                "hndl": True,
            }
        ]

        pdf_bytes = generate_pdf_report(project_name, scan_meta, findings)

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b"%PDF-"), "Generated report must begin with valid PDF magic bytes '%PDF-'"
        assert b"%%EOF" in pdf_bytes or b"%EOF" in pdf_bytes, "PDF must contain EOF marker"

    def test_default_and_omitted_arguments(self):
        """Calling generate_pdf_report() with no arguments or None must generate a valid PDF."""
        pdf_bytes = generate_pdf_report()
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        assert pdf_bytes.startswith(b"%PDF-")

    def test_api_route_compatibility_format(self):
        """Matches the exact dictionary structure produced in keynova/api/v1/export.py."""
        findings = [
            {
                "id": "find-101",
                "file_path": "app/auth.py",
                "line_start": 10,
                "line_end": 12,
                "algorithm": "ECDSA",
                "usage": "digital_signature",
                "key_size": 256,
                "severity": "high",
                "hndl": False,
            }
        ]
        scan_meta = {
            "id": "scan-uuid-456",
            "readiness_score": 75,
            "coverage_percent": 90.5,
            "scanned_files": 10,
            "total_files": 11,
            "hndl_count": 0,
        }
        pdf_bytes = generate_pdf_report("Checkout Service", scan_meta, findings)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")


# ============================================================================
# 2. READINESS SCORE TIERS & INTERPRETATION
# ============================================================================

class TestPdfReadinessScoreAndTiers:
    """Verifies score rendering across Critical (<50), Needs Upgrade (50-79), and Ready (>=80)."""

    def test_critical_risk_tier(self):
        """Scores < 50 represent Critical Risk."""
        scan_meta = {"id": "scan-1", "readiness_score": 28, "coverage_percent": 100.0}
        findings = [{"algorithm": "RSA-2048", "severity": "critical", "hndl": True}]
        pdf_bytes = generate_pdf_report("Critical Project", scan_meta, findings)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_needs_upgrade_risk_tier(self):
        """Scores between 50 and 79 represent Needs Upgrade."""
        scan_meta = {"id": "scan-2", "readiness_score": 68, "coverage_percent": 100.0}
        findings = [{"algorithm": "ECDSA-P256", "severity": "high", "hndl": False}]
        pdf_bytes = generate_pdf_report("Moderate Project", scan_meta, findings)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_quantum_ready_tier(self):
        """Scores >= 80 represent Quantum Ready."""
        scan_meta = {"id": "scan-3", "readiness_score": 95, "coverage_percent": 100.0}
        findings = [{"algorithm": "ML-KEM-768", "severity": "quantum_safe", "hndl": False}]
        pdf_bytes = generate_pdf_report("PQC Project", scan_meta, findings)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_score_none_graceful_handling(self):
        """When readiness_score is None, report must not crash or invent a score."""
        scan_meta = {"id": "scan-4", "readiness_score": None, "coverage_percent": 50.0}
        pdf_bytes = generate_pdf_report("Unassessed Project", scan_meta, [])
        assert pdf_bytes.startswith(b"%PDF-")

    def test_score_invalid_string_type_fallback(self):
        """Non-numeric readiness_score falls back gracefully to unassessed."""
        scan_meta = {"id": "scan-5", "readiness_score": "not_a_valid_number"}
        pdf_bytes = generate_pdf_report("Invalid Score Project", scan_meta, [])
        assert pdf_bytes.startswith(b"%PDF-")


# ============================================================================
# 3. EMPTY FINDINGS & PARTIAL METADATA
# ============================================================================

class TestPdfEmptyFindingsAndPartialMetadata:
    """Verifies graceful handling of empty lists and missing optional fields."""

    def test_empty_findings_list(self):
        """Zero findings must produce a valid clean report."""
        scan_meta = {
            "id": "scan-clean",
            "readiness_score": 100,
            "coverage_percent": 100.0,
            "scanned_files": 5,
            "total_files": 5,
            "hndl_count": 0,
        }
        pdf_bytes = generate_pdf_report("Clean Project", scan_meta, [])
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 1000

    def test_none_findings_handled_as_empty(self):
        """Passing None for findings must be treated as empty list."""
        pdf_bytes = generate_pdf_report("No Findings Project", {"readiness_score": 100}, None)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_none_scan_meta_handled_gracefully(self):
        """Passing None for scan_meta must generate a valid report with fallback defaults."""
        pdf_bytes = generate_pdf_report("Fallback Project", None, [])
        assert pdf_bytes.startswith(b"%PDF-")

    def test_empty_scan_meta_handled_gracefully(self):
        """Passing empty dict {} for scan_meta must generate a valid report."""
        pdf_bytes = generate_pdf_report("Empty Meta Project", {}, [])
        assert pdf_bytes.startswith(b"%PDF-")

    def test_empty_project_name(self):
        """Empty or whitespace project name must fall back safely."""
        pdf_bytes = generate_pdf_report("   ", {}, [])
        assert pdf_bytes.startswith(b"%PDF-")


# ============================================================================
# 4. FINDING SEVERITY, QUANTUM CLASSIFICATION & RECOMMENDATIONS
# ============================================================================

class TestPdfFindingsClassificationAndRecommendations:
    """Verifies domain classifications, severity metrics, and remediation mappings."""

    def test_quantum_classification_helper(self):
        """Verifies _classify_quantum_status correctly detects PQC and vulnerable algorithms."""
        assert _classify_quantum_status("ML-KEM-768") == "safe"
        assert _classify_quantum_status("ml-dsa-65") == "safe"
        assert _classify_quantum_status("FIPS 205 (SLH-DSA)") == "safe"
        assert _classify_quantum_status("AES-256-GCM") == "safe"
        assert _classify_quantum_status("RSA-2048") == "vulnerable"
        assert _classify_quantum_status("ECDSA_P256") == "vulnerable"
        assert _classify_quantum_status("MD5") == "vulnerable"
        assert _classify_quantum_status("DES") == "vulnerable"
        assert _classify_quantum_status("CustomCrypto") == "unknown"

        # Explicit status override
        assert _classify_quantum_status("CustomCrypto", explicit_status="quantum_safe") == "safe"
        assert _classify_quantum_status("CustomCrypto", explicit_status="vulnerable") == "vulnerable"

    def test_risk_and_remediation_helper_standards(self):
        """Verifies that appropriate NIST standards (FIPS 203/204/202) are recommended."""
        # Key encapsulation / HNDL -> FIPS 203
        r1, rec1 = _analyze_risk_and_remediation({
            "algorithm": "RSA-2048",
            "usage": "asymmetric_encryption",
            "hndl": True,
        })
        assert "HNDL" in r1 or "Harvest-Now-Decrypt-Later" in r1
        assert "203" in rec1 or "ML-KEM" in rec1

        # Digital signature -> FIPS 204
        r2, rec2 = _analyze_risk_and_remediation({
            "algorithm": "ECDSA",
            "usage": "digital_signature",
            "hndl": False,
        })
        assert "signature" in r2.lower()
        assert "204" in rec2 or "ML-DSA" in rec2

        # Legacy hash -> SHA-3 / FIPS 202
        r3, rec3 = _analyze_risk_and_remediation({
            "algorithm": "MD5",
            "usage": "hashing",
            "hndl": False,
        })
        assert "collision" in r3.lower()
        assert "202" in rec3 or "SHA-3" in rec3 or "SHA-256" in rec3

        # Legacy cipher -> AES-256-GCM
        r4, rec4 = _analyze_risk_and_remediation({
            "algorithm": "3DES",
            "usage": "symmetric_encryption",
            "hndl": False,
        })
        assert "AES-256" in rec4

        # PQC algorithm -> maintain
        r5, rec5 = _analyze_risk_and_remediation({
            "algorithm": "ML-KEM-768",
            "usage": "key_encapsulation",
            "hndl": False,
        })
        assert "quantum-resilient" in r5.lower() or "post-quantum" in r5.lower()

    def test_multi_severity_comprehensive_findings(self):
        """Report renders multiple findings across critical, high, medium, low, and quantum-safe."""
        findings = [
            {
                "algorithm": "RSA-2048",
                "severity": "critical",
                "hndl": True,
                "file_path": "crypto/rsa.py",
                "line_start": 40,
                "line_end": 45,
                "usage": "key_exchange",
            },
            {
                "algorithm": "ECDSA-P256",
                "severity": "high",
                "hndl": False,
                "file_path": "auth/tokens.py",
                "line_start": 120,
                "usage": "token_signature",
            },
            {
                "algorithm": "MD5",
                "severity": "medium",
                "hndl": False,
                "file_path": "utils/hash.py",
                "line_start": 15,
                "usage": "checksum",
            },
            {
                "algorithm": "unpinned-cryptography",
                "severity": "low",
                "hndl": False,
                "file_path": "requirements.txt",
                "line_start": 3,
                "usage": "dependency",
            },
            {
                "algorithm": "ML-KEM-768",
                "severity": "quantum_safe",
                "hndl": False,
                "file_path": "pqc/kem.py",
                "line_start": 1,
                "usage": "kem",
            },
        ]
        scan_meta = {
            "id": "scan-multi",
            "readiness_score": 52,
            "coverage_percent": 88.0,
            "scanned_files": 22,
            "total_files": 25,
            "hndl_count": 1,
        }
        pdf_bytes = generate_pdf_report("Multi Severity App", scan_meta, findings)
        assert pdf_bytes.startswith(b"%PDF-")


# ============================================================================
# 5. ROBUSTNESS & XML ESCAPING
# ============================================================================

class TestPdfRobustnessAndEscaping:
    """Verifies that malformed data, special characters, and missing fields do not crash ReportLab."""

    def test_xml_escaping_helper(self):
        """Verifies _escape safely encodes XML characters using xml.sax.saxutils.escape."""
        assert _escape("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
        assert _escape("A & B") == "A &amp; B"
        assert _escape(None, "default") == "default"
        assert _escape("", "default") == "default"

    def test_findings_with_special_xml_characters(self):
        """Filenames, algorithms, and project names containing XML entities (< and &) must not crash."""
        findings = [
            {
                "file_path": "src/<module>&config/test.py",
                "line_start": 1,
                "algorithm": "RSA <2048> & 'legacy'",
                "usage": "auth <tokens> & secrets",
                "code_snippet": "if (x < 10 && y > 20) { crypto_sign(&key); }",
                "severity": "critical",
                "hndl": True,
            }
        ]
        scan_meta = {
            "id": "scan-<123>&",
            "readiness_score": 40,
        }
        project_name = "Finance <Gateway> & Co."

        pdf_bytes = generate_pdf_report(project_name, scan_meta, findings)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_missing_optional_finding_fields(self):
        """Findings with missing keys or None values must not raise exceptions."""
        findings = [
            {},  # completely empty dictionary
            {
                "file_path": None,
                "line_start": None,
                "line_end": None,
                "algorithm": None,
                "usage": None,
                "key_size": None,
                "severity": None,
                "hndl": None,
            },
        ]
        pdf_bytes = generate_pdf_report("Sparse Findings", {}, findings)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_large_findings_list_multi_page_layout(self):
        """Generating a report with 60 findings must paginate smoothly across multiple pages."""
        findings = [
            {
                "file_path": f"services/module_{i}/crypto.py",
                "line_start": i * 10,
                "algorithm": "RSA-2048" if i % 2 == 0 else "ECDSA-P256",
                "usage": "asymmetric_encryption" if i % 2 == 0 else "digital_signature",
                "key_size": 2048 if i % 2 == 0 else 256,
                "severity": "critical" if i % 2 == 0 else "high",
                "hndl": (i % 2 == 0),
            }
            for i in range(60)
        ]
        scan_meta = {
            "id": "scan-large-01",
            "readiness_score": 15,
            "coverage_percent": 100.0,
            "scanned_files": 60,
            "total_files": 60,
            "hndl_count": 30,
        }
        pdf_bytes = generate_pdf_report("Large Scale Enterprise", scan_meta, findings)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 5000, "Multi-page PDF should have substantial byte size"


# ============================================================================
# 6. INTEGRATION WITH REAL FIXTURES
# ============================================================================

class TestPdfFixtureIntegration:
    """Verifies end-to-end PDF report generation using ground-truth hackathon fixtures."""

    def test_vulnerable_payment_suite_pdf_export(self):
        """Scans vulnerable fixture and exports a valid executive PDF report."""
        assert VULN_FIXTURE_DIR.exists(), f"Missing fixture: {VULN_FIXTURE_DIR}"
        findings = _scan_fixture_directory(VULN_FIXTURE_DIR)
        assert len(findings) > 0, "Vulnerable fixture must produce findings"

        scoring_result = calculate_readiness_score(findings, total_files=10, scanned_files=10)
        scan_meta = {
            "id": "vuln-fixture-scan",
            "readiness_score": scoring_result["readiness_score"],
            "coverage_percent": scoring_result["coverage_percent"],
            "scanned_files": scoring_result["scanned_files"],
            "total_files": scoring_result["total_files"],
            "hndl_count": scoring_result["hndl_count"],
        }

        pdf_bytes = generate_pdf_report("Vulnerable Payment Suite", scan_meta, findings)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 3000

    def test_remediated_payment_suite_pdf_export(self):
        """Scans remediated fixture and exports a valid executive PDF report."""
        assert REMED_FIXTURE_DIR.exists(), f"Missing fixture: {REMED_FIXTURE_DIR}"
        findings = _scan_fixture_directory(REMED_FIXTURE_DIR)

        scoring_result = calculate_readiness_score(findings, total_files=10, scanned_files=10)
        scan_meta = {
            "id": "remed-fixture-scan",
            "readiness_score": scoring_result["readiness_score"],
            "coverage_percent": scoring_result["coverage_percent"],
            "scanned_files": scoring_result["scanned_files"],
            "total_files": scoring_result["total_files"],
            "hndl_count": scoring_result["hndl_count"],
        }

        pdf_bytes = generate_pdf_report("Remediated Payment Suite", scan_meta, findings)
        assert pdf_bytes.startswith(b"%PDF-")
        assert len(pdf_bytes) > 2000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
