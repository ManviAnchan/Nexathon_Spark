"""
Unit and integration test suite for Keynova's Readiness Scoring Engine
(scoring.py) and Scan Diff Comparator (diff.py).

Verifies mathematical properties, boundary conditions, edge cases,
and ground-truth comparisons against vulnerable and remediated payment suites.
"""

from pathlib import Path
from typing import List, Dict, Any
import pytest

from keynova.services.intelligence.scoring import (
    calculate_readiness_score,
    SEVERITY_WEIGHTS,
)
from keynova.services.intelligence.diff import compare_scans

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "test-fixtures"
VULN_FIXTURE_DIR = FIXTURES_DIR / "vulnerable_payment_suite"
REMED_FIXTURE_DIR = FIXTURES_DIR / "remediated_payment_suite"


# ============================================================================
# 1. READINESS SCORING ENGINE (calculate_readiness_score) TESTS
# ============================================================================

class TestReadinessScoringEngine:
    """Test suite for calculate_readiness_score() in scoring.py."""

    def test_clean_project_scores_100(self):
        """A fully scanned project with zero findings must score 100/100."""
        report = calculate_readiness_score(findings=[], total_files=10, scanned_files=10)
        assert report["readiness_score"] == 100
        assert report["coverage_percent"] == 100.0
        assert report["total_penalty"] == 0.0
        assert report["hndl_count"] == 0
        assert report["severity_counts"]["critical"] == 0
        assert report["severity_counts"]["high"] == 0

    def test_score_bounded_between_0_and_100_extreme_penalties(self):
        """Scores must never drop below 0 even under extreme cumulative penalties."""
        extreme_findings = [
            {"severity": "critical", "hndl": True, "confidence": 1.0}
            for _ in range(50)
        ]
        report = calculate_readiness_score(
            findings=extreme_findings, total_files=5, scanned_files=5
        )
        assert report["readiness_score"] == 0
        assert report["total_penalty"] == 100.0  # capped at 100.0
        assert 0 <= report["readiness_score"] <= 100

    def test_score_deterministic_consistency(self):
        """Repeated evaluations of identical findings must yield identical results (0.00 variance)."""
        findings = [
            {"severity": "critical", "hndl": True, "confidence": 0.95},
            {"severity": "high", "hndl": False, "confidence": 0.90},
            {"severity": "low", "hndl": False, "confidence": 1.0},
        ]
        scores = [
            calculate_readiness_score(findings, total_files=20, scanned_files=18)["readiness_score"]
            for _ in range(50)
        ]
        assert len(set(scores)) == 1, "Score variance must be exactly 0.00 across runs"

    def test_partial_coverage_penalization_formula(self):
        """
        Uninspected files must penalize the score according to:
        Coverage Factor C = 0.5 + 0.5 * (scanned_files / total_files)
        """
        # When 0 findings but only 10% scanned (1 of 10):
        # Base score = 100, C = 0.5 + 0.5 * (1/10) = 0.55 -> Score = round(100 * 0.55) = 55
        rep_10_pct = calculate_readiness_score(findings=[], total_files=10, scanned_files=1)
        assert rep_10_pct["coverage_percent"] == 10.0
        assert rep_10_pct["readiness_score"] == 55

        # When 0 findings and 50% scanned (5 of 10):
        # Base score = 100, C = 0.5 + 0.5 * (5/10) = 0.75 -> Score = round(100 * 0.75) = 75
        rep_50_pct = calculate_readiness_score(findings=[], total_files=10, scanned_files=5)
        assert rep_50_pct["coverage_percent"] == 50.0
        assert rep_50_pct["readiness_score"] == 75

        # When 0 findings and 100% scanned:
        # Base score = 100, C = 1.0 -> Score = 100
        rep_100_pct = calculate_readiness_score(findings=[], total_files=10, scanned_files=10)
        assert rep_100_pct["coverage_percent"] == 100.0
        assert rep_100_pct["readiness_score"] == 100

    def test_zero_file_inputs_handled_safely(self):
        """Zero files or empty counts must not cause ZeroDivisionError or crash."""
        report = calculate_readiness_score(findings=[], total_files=0, scanned_files=0)
        assert 0 <= report["readiness_score"] <= 100
        assert report["total_files"] == 1
        assert report["scanned_files"] == 1
        assert report["coverage_percent"] == 100.0

    def test_severity_weights_and_hndl_multipliers(self):
        """Verifies each severity weight, the 1.4x HNDL multiplier, and confidence scaling."""
        # Critical non-HNDL: weight 25.0 * 1.0 * 1.0 = 25.0 -> Score: 100 - 25 = 75
        r_crit = calculate_readiness_score(
            [{"severity": "critical", "hndl": False, "confidence": 1.0}], 1, 1
        )
        assert r_crit["total_penalty"] == 25.0
        assert r_crit["readiness_score"] == 75

        # Critical with HNDL: weight 25.0 * 1.4 * 1.0 = 35.0 -> Score: 100 - 35 = 65
        r_crit_hndl = calculate_readiness_score(
            [{"severity": "critical", "hndl": True, "confidence": 1.0}], 1, 1
        )
        assert r_crit_hndl["total_penalty"] == 35.0
        assert r_crit_hndl["readiness_score"] == 65
        assert r_crit_hndl["hndl_count"] == 1

        # High: weight 12.0 * 1.0 * 1.0 = 12.0 -> Score: 88
        r_high = calculate_readiness_score(
            [{"severity": "high", "hndl": False, "confidence": 1.0}], 1, 1
        )
        assert r_high["total_penalty"] == 12.0
        assert r_high["readiness_score"] == 88

        # Medium: weight 5.0 * 1.0 * 1.0 = 5.0 -> Score: 95
        r_med = calculate_readiness_score(
            [{"severity": "medium", "hndl": False, "confidence": 1.0}], 1, 1
        )
        assert r_med["total_penalty"] == 5.0
        assert r_med["readiness_score"] == 95

        # Low: weight 2.0 * 1.0 * 1.0 = 2.0 -> Score: 98
        r_low = calculate_readiness_score(
            [{"severity": "low", "hndl": False, "confidence": 1.0}], 1, 1
        )
        assert r_low["total_penalty"] == 2.0
        assert r_low["readiness_score"] == 98

        # Quantum Safe: weight 0.0 -> Score: 100
        r_qs = calculate_readiness_score(
            [{"severity": "quantum_safe", "hndl": False, "confidence": 1.0}], 1, 1
        )
        assert r_qs["total_penalty"] == 0.0
        assert r_qs["readiness_score"] == 100

        # Confidence factor scaling: 25.0 * 1.0 * 0.8 = 20.0 -> Score: 80
        r_conf = calculate_readiness_score(
            [{"severity": "critical", "hndl": False, "confidence": 0.8}], 1, 1
        )
        assert r_conf["total_penalty"] == 20.0
        assert r_conf["readiness_score"] == 80

    def test_unknown_severity_fallback_to_low(self):
        """Unknown or mislabeled severity strings fallback to 'low' severity (weight 2.0)."""
        report = calculate_readiness_score(
            [{"severity": "unrecognized_tier", "hndl": False, "confidence": 1.0}], 1, 1
        )
        assert report["severity_counts"]["low"] == 1
        assert report["total_penalty"] == 2.0
        assert report["readiness_score"] == 98

    def test_vulnerable_scores_46_and_remediated_scores_100_delta_54(self):
        """
        Explicit verification required by specification:
        - Vulnerable fixture findings produce total penalty of 54.0:
          * 1 Critical with HNDL: 25.0 * 1.4 = 35.0
          * 1 High: 12.0 * 1.0 = 12.0
          * 1 Medium: 5.0 * 1.0 = 5.0
          * 1 Low: 2.0 * 1.0 = 2.0
          Total Penalty = 54.0 -> Readiness Score = round(100 - 54) * 1.0 = 46/100.
        - Remediated fixture produces 0 findings:
          Total Penalty = 0.0 -> Readiness Score = 100/100.
        - Scan diff delta:
          Target (100) - Baseline (46) = +54 points leap.
          Verification status = 'verified_clean'.
        """
        vuln_findings = [
            {"fingerprint": "fp_rsa", "algorithm": "RSA-2048", "severity": "critical", "hndl": True, "confidence": 1.0},
            {"fingerprint": "fp_ecc", "algorithm": "ECC-SECP256R1", "severity": "high", "hndl": False, "confidence": 1.0},
            {"fingerprint": "fp_sha1", "algorithm": "SHA-1", "severity": "medium", "hndl": False, "confidence": 1.0},
            {"fingerprint": "fp_md5", "algorithm": "MD5", "severity": "low", "hndl": False, "confidence": 1.0},
        ]
        remed_findings = []

        rep_vuln = calculate_readiness_score(vuln_findings, total_files=10, scanned_files=10)
        assert rep_vuln["readiness_score"] == 46
        assert rep_vuln["total_penalty"] == 54.0
        assert rep_vuln["hndl_count"] == 1
        assert rep_vuln["severity_counts"]["critical"] == 1
        assert rep_vuln["severity_counts"]["high"] == 1
        assert rep_vuln["severity_counts"]["medium"] == 1
        assert rep_vuln["severity_counts"]["low"] == 1

        rep_remed = calculate_readiness_score(remed_findings, total_files=10, scanned_files=10)
        assert rep_remed["readiness_score"] == 100
        assert rep_remed["total_penalty"] == 0.0
        assert rep_remed["hndl_count"] == 0

        diff = compare_scans(
            baseline_findings=vuln_findings,
            target_findings=remed_findings,
            baseline_score=rep_vuln["readiness_score"],
            target_score=rep_remed["readiness_score"],
        )
        assert diff["resolved_count"] == 4
        assert diff["added_count"] == 0
        assert diff["unchanged_count"] == 0
        assert diff["readiness_delta"] == 54
        assert diff["verification_status"] == "verified_clean"


# ============================================================================
# 2. SCAN DIFF COMPARATOR (compare_scans) TESTS
# ============================================================================

class TestScanDiffComparator:
    """Test suite for compare_scans() in diff.py."""

    def test_identical_scans(self):
        """Comparing identical findings yields zero resolved, zero added, and partial status."""
        findings = [
            {"fingerprint": "fp_rsa", "algorithm": "RSA", "file_path": "crypto.py"},
            {"fingerprint": "fp_md5", "algorithm": "MD5", "file_path": "hasher.py"},
        ]
        diff = compare_scans(findings, findings, baseline_score=60, target_score=60)
        assert diff["resolved_count"] == 0
        assert diff["added_count"] == 0
        assert diff["unchanged_count"] == 2
        assert diff["readiness_delta"] == 0
        assert diff["verification_status"] == "partial_remediation"
        assert len(diff["resolved_findings"]) == 0
        assert len(diff["added_findings"]) == 0

    def test_all_findings_resolved_verified_clean(self):
        """When target findings are empty, verification_status must be 'verified_clean'."""
        baseline = [
            {"fingerprint": "fp_rsa", "algorithm": "RSA", "file_path": "crypto.py"},
            {"fingerprint": "fp_ecc", "algorithm": "ECC", "file_path": "auth.py"},
        ]
        target = []
        diff = compare_scans(baseline, target, baseline_score=50, target_score=100)
        assert diff["resolved_count"] == 2
        assert diff["added_count"] == 0
        assert diff["unchanged_count"] == 0
        assert diff["readiness_delta"] == 50
        assert diff["verification_status"] == "verified_clean"
        assert len(diff["resolved_findings"]) == 2

    def test_partially_resolved_findings(self):
        """Resolving some findings while leaving others produces 'partial_remediation'."""
        baseline = [
            {"fingerprint": "fp_1", "algorithm": "RSA"},
            {"fingerprint": "fp_2", "algorithm": "ECC"},
            {"fingerprint": "fp_3", "algorithm": "MD5"},
        ]
        target = [
            {"fingerprint": "fp_2", "algorithm": "ECC"},  # fp_1 and fp_3 resolved
        ]
        diff = compare_scans(baseline, target, baseline_score=40, target_score=75)
        assert diff["resolved_count"] == 2
        assert diff["added_count"] == 0
        assert diff["unchanged_count"] == 1
        assert diff["readiness_delta"] == 35
        assert diff["verification_status"] == "partial_remediation"
        resolved_fps = {f["fingerprint"] for f in diff["resolved_findings"]}
        assert resolved_fps == {"fp_1", "fp_3"}

    def test_regression_detected_when_new_vulnerabilities_introduced(self):
        """
        When new findings are introduced and the readiness delta is negative,
        verification_status must be 'regression_detected'.
        """
        baseline = [
            {"fingerprint": "fp_1", "algorithm": "MD5"},
        ]
        target = [
            {"fingerprint": "fp_1", "algorithm": "MD5"},
            {"fingerprint": "fp_2_new_rsa", "algorithm": "RSA"},  # new critical debt added
        ]
        diff = compare_scans(baseline, target, baseline_score=90, target_score=50)
        assert diff["resolved_count"] == 0
        assert diff["added_count"] == 1
        assert diff["unchanged_count"] == 1
        assert diff["readiness_delta"] == -40
        assert diff["verification_status"] == "regression_detected"
        assert diff["added_findings"][0]["fingerprint"] == "fp_2_new_rsa"


# ============================================================================
# 3. FIXTURE INTEGRATION TESTS (optional when scanner & fixtures are available)
# ============================================================================

def _can_run_fixture_ast_scan() -> bool:
    """Helper to check if AST scanners and fixture directories are available."""
    try:
        from keynova.services.scanner.python_ast import scan_python_file  # noqa: F401
        from keynova.services.scanner.manifests import scan_manifest_file  # noqa: F401
        return VULN_FIXTURE_DIR.exists() and REMED_FIXTURE_DIR.exists()
    except ImportError:
        return False


@pytest.mark.skipif(not _can_run_fixture_ast_scan(), reason="Scanner modules or fixtures not yet merged into this branch")
class TestFixtureScoringAndDiffIntegration:
    """
    Integration tests against actual sample test fixture codebases:
    - test-fixtures/vulnerable_payment_suite
    - test-fixtures/remediated_payment_suite
    """

    def test_fixture_directories_exist(self):
        assert VULN_FIXTURE_DIR.exists(), f"Missing {VULN_FIXTURE_DIR}"
        assert REMED_FIXTURE_DIR.exists(), f"Missing {REMED_FIXTURE_DIR}"

    def test_vulnerable_fixture_scan_and_readiness_scoring(self):
        from keynova.services.scanner.python_ast import scan_python_file
        from keynova.services.scanner.manifests import scan_manifest_file

        findings = []
        for f in sorted(VULN_FIXTURE_DIR.rglob("*")):
            if f.is_file() and not any(part in [".git", "__pycache__", ".venv"] for part in f.parts):
                if f.suffix == ".py":
                    py_findings = scan_python_file(f, relative_to=VULN_FIXTURE_DIR)
                    findings.extend([item.to_dict() for item in py_findings])
                elif f.name.lower() in ["requirements.txt", "package.json"]:
                    findings.extend(scan_manifest_file(f, relative_to=VULN_FIXTURE_DIR))

        report = calculate_readiness_score(findings, total_files=4, scanned_files=4)
        assert 45 <= report["readiness_score"] <= 50
        assert report["coverage_percent"] == 100.0

    def test_remediated_fixture_scan_and_readiness_scoring(self):
        from keynova.services.scanner.python_ast import scan_python_file
        from keynova.services.scanner.manifests import scan_manifest_file

        findings = []
        for f in sorted(REMED_FIXTURE_DIR.rglob("*")):
            if f.is_file() and not any(part in [".git", "__pycache__", ".venv"] for part in f.parts):
                if f.suffix == ".py":
                    py_findings = scan_python_file(f, relative_to=REMED_FIXTURE_DIR)
                    findings.extend([item.to_dict() for item in py_findings])
                elif f.name.lower() in ["requirements.txt", "package.json"]:
                    findings.extend(scan_manifest_file(f, relative_to=REMED_FIXTURE_DIR))

        report = calculate_readiness_score(findings, total_files=4, scanned_files=4)
        assert report["readiness_score"] == 100
        assert report["coverage_percent"] == 100.0
