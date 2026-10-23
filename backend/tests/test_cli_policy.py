"""
Comprehensive test suite for Keynova's CLI Policy Evaluator
(backend/keynova/cli/policy.py and backend/keynova/cli/main.py).

Validates:
1. Policy-compliant inputs return exit code 0.
2. Prohibited algorithms trigger violations and exit code 1.
3. Findings exceeding permitted severity trigger violations and exit code 1.
4. Empty findings are handled gracefully.
5. Malformed input (invalid JSON, non-existent files) produces clear errors and exit code 2.
6. Missing optional fields in findings do not crash the evaluator.
7. Unknown or insufficient metadata does not falsely establish compliance.
8. Multiple distinct violations are identified and reported with location details.
9. Machine-readable JSON output (--json) and output file export (--output).
10. `scan <directory>` subcommand syntax and policy flags (min-readiness >= 80, block-hndl=True).
11. Actual OS process exit codes via subprocess execution.
"""

import os
import sys
from pathlib import Path
import json
import subprocess
from typing import List, Dict, Any
import pytest

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from keynova.cli.policy import (
    evaluate_policy,
    load_policy,
    DEFAULT_POLICY,
    PolicyViolation,
)
from keynova.cli.main import run_cli

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "test-fixtures"
VULN_FIXTURE_DIR = FIXTURES_DIR / "vulnerable_payment_suite"
REMED_FIXTURE_DIR = FIXTURES_DIR / "remediated_payment_suite"


# ============================================================================
# 1. POLICY EVALUATION ENGINE UNIT TESTS
# ============================================================================

class TestPolicyEvaluationEngine:
    """Tests core policy evaluation logic against explicit rules."""

    def test_policy_compliant_findings_pass(self):
        """Findings complying with all thresholds must pass with zero violations."""
        findings = [
            {
                "id": "f-1",
                "algorithm": "ML-KEM-768",
                "severity": "quantum_safe",
                "hndl": False,
                "quantum_status": "safe",
                "file_path": "crypto/kem.py",
                "line_start": 10,
            }
        ]
        scan_meta = {"readiness_score": 95, "hndl_count": 0, "coverage_percent": 100.0}
        policy = {
            "min_readiness_score": 80,
            "block_hndl": True,
            "max_severity": "high",
            "disallowed_algorithms": ["MD5", "SHA-1"],
            "require_quantum_safe": True,
        }

        result = evaluate_policy(findings=findings, policy=policy, scan_meta=scan_meta)

        assert result["passed"] is True
        assert len(result["violations"]) == 0
        assert result["summary"]["total_findings"] == 1
        assert result["summary"]["violations_count"] == 0

    def test_prohibited_algorithm_triggers_violation(self):
        """Disallowed algorithms (e.g. MD5, SHA-1, DES) must trigger explicit violations."""
        findings = [
            {
                "id": "f-md5",
                "algorithm": "hashlib.md5",
                "severity": "medium",
                "hndl": False,
                "file_path": "utils/hash.py",
                "line_start": 42,
            }
        ]
        policy = {
            "disallowed_algorithms": ["MD5", "DES"],
            "block_hndl": False,
            "min_readiness_score": 0,
        }

        result = evaluate_policy(findings=findings, policy=policy)

        assert result["passed"] is False
        assert len(result["violations"]) == 1
        violation = result["violations"][0]
        assert violation["rule"] == "disallowed_algorithm"
        assert "MD5" in violation["message"]
        assert violation["file_path"] == "utils/hash.py"
        assert violation["line"] == 42

    def test_finding_exceeding_max_severity_triggers_violation(self):
        """Findings with severity exceeding max_severity must trigger violations."""
        findings = [
            {"algorithm": "AES-128", "severity": "medium", "file_path": "a.py", "line_start": 5},
            {"algorithm": "RSA-1024", "severity": "critical", "file_path": "b.py", "line_start": 20},
        ]
        policy = {
            "max_severity": "medium",
            "block_hndl": False,
            "min_readiness_score": 0,
        }

        result = evaluate_policy(findings=findings, policy=policy)

        assert result["passed"] is False
        assert len(result["violations"]) == 1
        assert result["violations"][0]["rule"] == "max_severity_exceeded"
        assert "CRITICAL" in result["violations"][0]["message"]
        assert result["violations"][0]["file_path"] == "b.py"

    def test_hndl_blocking_rule(self):
        """Findings with hndl=True must trigger violations when block_hndl is enabled."""
        findings = [
            {
                "algorithm": "ECDH-P256",
                "severity": "high",
                "hndl": True,
                "file_path": "auth/session.py",
                "line_start": 88,
            }
        ]
        policy = {"block_hndl": True, "min_readiness_score": 0}

        result = evaluate_policy(findings=findings, policy=policy)

        assert result["passed"] is False
        assert any(v["rule"] == "block_hndl" for v in result["violations"])

    def test_empty_findings_handled_correctly(self):
        """Zero findings must cleanly pass policy checks."""
        result = evaluate_policy(findings=[], policy=DEFAULT_POLICY, scan_meta={"readiness_score": 100})
        assert result["passed"] is True
        assert len(result["violations"]) == 0
        assert result["summary"]["total_findings"] == 0

    def test_missing_optional_fields_do_not_crash(self):
        """Findings with missing keys or None values must not raise exceptions."""
        findings = [
            {},  # completely empty dictionary
            {
                "algorithm": None,
                "severity": None,
                "hndl": None,
                "file_path": None,
                "line_start": None,
                "key_size": None,
            },
        ]
        result = evaluate_policy(findings=findings, policy=DEFAULT_POLICY)
        assert isinstance(result, dict)
        assert "passed" in result

    def test_unknown_or_insufficient_info_does_not_falsely_establish_pqc_compliance(self):
        """
        SECURITY REQUIREMENT: When require_quantum_safe is active, findings lacking
        verifiable PQC indicators or algorithm metadata must fail, not silently pass.
        """
        findings = [
            {"algorithm": None, "quantum_status": None, "file_path": "opaque.py", "line_start": 1}
        ]
        policy = {"require_quantum_safe": True, "block_hndl": False, "min_readiness_score": 0}

        result = evaluate_policy(findings=findings, policy=policy)

        assert result["passed"] is False
        assert any(v["rule"] == "require_quantum_safe" for v in result["violations"])
        assert "Cannot verify quantum safety" in result["violations"][0]["message"]

    def test_multiple_violations_reported_clearly(self):
        """Multiple distinct policy violations must all be captured and reported."""
        findings = [
            {"algorithm": "MD5", "severity": "medium", "hndl": False, "file_path": "a.py", "line_start": 10},
            {"algorithm": "RSA-1024", "severity": "critical", "hndl": True, "file_path": "b.py", "line_start": 20},
        ]
        scan_meta = {"readiness_score": 40}
        policy = {
            "min_readiness_score": 80,
            "block_hndl": True,
            "disallowed_algorithms": ["MD5"],
            "max_severity": "high",
        }

        result = evaluate_policy(findings=findings, policy=policy, scan_meta=scan_meta)

        assert result["passed"] is False
        rules = [v["rule"] for v in result["violations"]]
        assert "min_readiness_score" in rules
        assert "disallowed_algorithm" in rules
        assert "block_hndl" in rules
        assert "max_severity_exceeded" in rules
        assert len(result["violations"]) == 4

    def test_minimum_key_size_enforcement(self):
        """Sub-standard key sizes must trigger minimum_key_size violations."""
        findings = [
            {"algorithm": "RSA", "key_size": 1024, "file_path": "keys.py", "line_start": 14}
        ]
        policy = {
            "min_key_sizes": {"rsa": 2048},
            "block_hndl": False,
            "min_readiness_score": 0,
        }

        result = evaluate_policy(findings=findings, policy=policy)

        assert result["passed"] is False
        assert any(v["rule"] == "minimum_key_size" for v in result["violations"])
        assert "1024" in result["violations"][0]["message"]
        assert "2048" in result["violations"][0]["message"]


# ============================================================================
# 2. CLI MAIN EXECUTION & PROCESS EXIT CODE TESTS
# ============================================================================

class TestCliCommandExecutionAndExitCodes:
    """Tests CLI entrypoint behavior, argument parsing, and process exit codes."""

    def test_cli_exit_code_0_on_compliant_repo(self):
        """Scanning remediated_payment_suite fixture must exit with code 0."""
        assert REMED_FIXTURE_DIR.exists()
        with pytest.raises(SystemExit) as exc_info:
            run_cli([str(REMED_FIXTURE_DIR), "--min-readiness", "80"])
        assert exc_info.value.code == 0

    def test_cli_exit_code_0_with_scan_subcommand(self):
        """`keynova-cli scan <directory>` syntax must be supported and return exit code 0."""
        assert REMED_FIXTURE_DIR.exists()
        with pytest.raises(SystemExit) as exc_info:
            run_cli(["scan", str(REMED_FIXTURE_DIR), "--min-readiness", "80"])
        assert exc_info.value.code == 0

    def test_cli_exit_code_1_on_vulnerable_repo(self):
        """Scanning vulnerable_payment_suite fixture must exit with code 1."""
        assert VULN_FIXTURE_DIR.exists()
        with pytest.raises(SystemExit) as exc_info:
            run_cli([str(VULN_FIXTURE_DIR), "--min-readiness", "80"])
        assert exc_info.value.code == 1

    def test_cli_exit_code_1_with_scan_subcommand_on_vulnerable_repo(self):
        """`keynova-cli scan <directory>` on vulnerable repository must exit with code 1."""
        assert VULN_FIXTURE_DIR.exists()
        with pytest.raises(SystemExit) as exc_info:
            run_cli(["scan", str(VULN_FIXTURE_DIR), "--min-readiness", "80"])
        assert exc_info.value.code == 1

    def test_cli_exit_code_0_on_clean_findings_json_file(self, tmp_path):
        """Evaluating clean findings JSON file must exit with code 0."""
        clean_file = tmp_path / "clean_findings.json"
        clean_file.write_text(json.dumps([
            {"algorithm": "AES-256-GCM", "severity": "low", "hndl": False}
        ]), encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            run_cli(["--findings", str(clean_file), "--min-readiness", "0"])
        assert exc_info.value.code == 0

    def test_cli_exit_code_1_on_disallowed_algorithm_flag(self, tmp_path):
        """CLI flag --disallow-algorithms must trigger exit code 1 when matched."""
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps([
            {"algorithm": "MD5", "severity": "medium", "hndl": False}
        ]), encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            run_cli(["--findings", str(findings_file), "--disallow-algorithms", "MD5", "--min-readiness", "0"])
        assert exc_info.value.code == 1

    def test_cli_exit_code_1_on_max_severity_flag(self, tmp_path):
        """CLI flag --max-severity must trigger exit code 1 when severity exceeded."""
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps([
            {"algorithm": "CustomCrypto", "severity": "critical", "hndl": False}
        ]), encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            run_cli(["--findings", str(findings_file), "--max-severity", "high", "--min-readiness", "0"])
        assert exc_info.value.code == 1

    def test_cli_exit_code_2_on_nonexistent_target_dir(self):
        """Non-existent target path must exit with code 2."""
        with pytest.raises(SystemExit) as exc_info:
            run_cli(["nonexistent_directory_xyz_123"])
        assert exc_info.value.code == 2

    def test_cli_exit_code_2_on_nonexistent_findings_file(self):
        """Non-existent findings file must exit with code 2."""
        with pytest.raises(SystemExit) as exc_info:
            run_cli(["--findings", "nonexistent_findings.json"])
        assert exc_info.value.code == 2

    def test_cli_exit_code_2_on_malformed_json_findings_file(self, tmp_path):
        """Malformed findings JSON file must exit with code 2."""
        bad_json_file = tmp_path / "corrupt.json"
        bad_json_file.write_text("{ unquoted_key: not_json }", encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            run_cli(["--findings", str(bad_json_file)])
        assert exc_info.value.code == 2

    def test_cli_exit_code_2_on_malformed_policy_file(self, tmp_path):
        """Malformed policy JSON file must exit with code 2."""
        findings_file = tmp_path / "findings.json"
        findings_file.write_text("[]", encoding="utf-8")
        bad_policy = tmp_path / "bad_policy.json"
        bad_policy.write_text("not_valid_json", encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            run_cli(["--findings", str(findings_file), "--policy", str(bad_policy)])
        assert exc_info.value.code == 2

    def test_cli_exit_code_2_when_no_arguments_provided(self):
        """Invoking CLI with zero arguments must exit with code 2."""
        with pytest.raises(SystemExit) as exc_info:
            run_cli([])
        assert exc_info.value.code == 2

    def test_cli_json_output_mode(self, tmp_path, capsys):
        """Running with --json outputs valid JSON to stdout."""
        clean_file = tmp_path / "findings.json"
        clean_file.write_text("[]", encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            run_cli(["--findings", str(clean_file), "--json"])
        assert exc_info.value.code == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["passed"] is True
        assert "summary" in data
        assert "violations" in data

    def test_cli_output_file_export(self, tmp_path):
        """Running with --output writes evaluation JSON report to specified path."""
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps([
            {"algorithm": "DES", "severity": "critical", "hndl": False}
        ]), encoding="utf-8")
        output_file = tmp_path / "reports" / "evaluation.json"

        with pytest.raises(SystemExit) as exc_info:
            run_cli([
                "--findings", str(findings_file),
                "--disallow-algorithms", "DES",
                "--output", str(output_file)
            ])
        assert exc_info.value.code == 1

        assert output_file.exists()
        saved_data = json.loads(output_file.read_text(encoding="utf-8"))
        assert saved_data["passed"] is False
        assert len(saved_data["violations"]) > 0

    def test_cli_custom_policy_file_integration(self, tmp_path):
        """Custom policy JSON file is loaded and enforced."""
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps([
            {"algorithm": "RC4", "severity": "medium", "hndl": False}
        ]), encoding="utf-8")

        policy_file = tmp_path / "strict_policy.json"
        policy_file.write_text(json.dumps({
            "disallowed_algorithms": ["RC4"],
            "block_hndl": False,
            "min_readiness_score": 0
        }), encoding="utf-8")

        with pytest.raises(SystemExit) as exc_info:
            run_cli(["--findings", str(findings_file), "--policy", str(policy_file)])
        assert exc_info.value.code == 1


# ============================================================================
# 3. ACTUAL OS SUBPROCESS PROCESS EXIT CODE VERIFICATION
# ============================================================================

class TestCliSubprocessExecution:
    """Spawns Python sub-processes to verify true OS exit codes (0, 1, 2)."""

    def test_subprocess_exit_code_0(self):
        """Process exit code must be 0 for remediated suite."""
        cmd = [
            sys.executable,
            "-m", "keynova.cli.main",
            "scan",
            str(REMED_FIXTURE_DIR),
            "--min-readiness", "80"
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(backend_dir),
            env={**os.environ, "PYTHONPATH": str(backend_dir)}
        )
        assert proc.returncode == 0
        assert "CI/CD GATING PASSED" in proc.stdout

    def test_subprocess_exit_code_1(self):
        """Process exit code must be 1 for vulnerable suite."""
        cmd = [
            sys.executable,
            "-m", "keynova.cli.main",
            "scan",
            str(VULN_FIXTURE_DIR),
            "--min-readiness", "80"
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(backend_dir),
            env={**os.environ, "PYTHONPATH": str(backend_dir)}
        )
        assert proc.returncode == 1
        assert "CI/CD GATING FAILED" in proc.stdout

    def test_subprocess_exit_code_2_on_error(self):
        """Process exit code must be 2 for non-existent target."""
        cmd = [
            sys.executable,
            "-m", "keynova.cli.main",
            "nonexistent_directory_404"
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(backend_dir),
            env={**os.environ, "PYTHONPATH": str(backend_dir)}
        )
        assert proc.returncode == 2
        assert "does not exist" in proc.stderr or "does not exist" in proc.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
