import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from keynova.main import app
from keynova.services.exporters.sarif import generate_sarif_report, HNDL_ADVISORY
from keynova.cli.main import run_cli

client = TestClient(app)


class TestSarifReportGeneration:
    """Tests OASIS SARIF v2.1.0 document generation and schema compliance."""

    def test_sarif_empty_findings(self):
        doc = generate_sarif_report([], project_name="Empty Project", scan_id="scan-0")
        assert doc["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "Keynova"
        assert len(run["tool"]["driver"]["rules"]) == 0
        assert len(run["results"]) == 0

    def test_sarif_rule_and_severity_mappings(self):
        findings = [
            {
                "id": "f-1",
                "rule_id": "PYTHON_RSA_KEYGEN",
                "algorithm": "RSA-2048",
                "usage": "key_generation",
                "severity": "critical",
                "hndl": True,
                "file_path": "backend/crypto.py",
                "line_start": 10,
                "line_end": 12,
                "code_snippet": "rsa.generate_private_key(65537, 2048)",
                "evidence": "RSA is broken by Shor's algorithm."
            },
            {
                "id": "f-2",
                "rule_id": "PYTHON_ECC_KEYGEN",
                "algorithm": "ECC-SECP256R1",
                "usage": "token_signing",
                "severity": "high",
                "hndl": True,
                "file_path": "backend/auth.py",
                "line_start": 25,
                "line_end": 25,
                "code_snippet": "ec.generate_private_key(ec.SECP256R1())",
                "evidence": "ECC is vulnerable to CRQC."
            },
            {
                "id": "f-3",
                "rule_id": "PYTHON_MD5_HASH",
                "algorithm": "MD5",
                "usage": "password_hashing",
                "severity": "medium",
                "hndl": False,
                "file_path": "backend/hasher.py",
                "line_start": 5,
                "line_end": 5,
                "code_snippet": "hashlib.md5(b'x').hexdigest()",
                "evidence": "Collision attacks on MD5."
            },
            {
                "id": "f-4",
                "rule_id": "PYTHON_SHA1_HASH",
                "algorithm": "SHA-1",
                "usage": "hashing",
                "severity": "low",
                "hndl": False,
                "file_path": "backend/legacy.py",
                "line_start": 15,
                "line_end": 15,
                "code_snippet": "hashlib.sha1(b'y').hexdigest()",
                "evidence": "SHA-1 deprecation."
            }
        ]

        doc = generate_sarif_report(findings, project_name="Test Payment Suite", scan_id="scan-1")
        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        results = run["results"]

        assert len(rules) == 4
        assert len(results) == 4

        # Validate Rule IDs and severities
        rule_map = {r["id"]: r for r in rules}
        assert "PYTHON_RSA_KEYGEN" in rule_map
        assert rule_map["PYTHON_RSA_KEYGEN"]["defaultConfiguration"]["level"] == "error"
        assert rule_map["PYTHON_RSA_KEYGEN"]["properties"]["security-severity"] == "9.5"
        assert "hndl" in rule_map["PYTHON_RSA_KEYGEN"]["properties"]["tags"]

        assert rule_map["PYTHON_ECC_KEYGEN"]["defaultConfiguration"]["level"] == "error"
        assert rule_map["PYTHON_ECC_KEYGEN"]["properties"]["security-severity"] == "8.0"

        assert rule_map["PYTHON_MD5_HASH"]["defaultConfiguration"]["level"] == "warning"
        assert rule_map["PYTHON_MD5_HASH"]["properties"]["security-severity"] == "5.5"

        assert rule_map["PYTHON_SHA1_HASH"]["defaultConfiguration"]["level"] == "warning"
        assert rule_map["PYTHON_SHA1_HASH"]["properties"]["security-severity"] == "2.5"

        # Validate Results and locations
        res_0 = results[0]
        assert res_0["ruleId"] == "PYTHON_RSA_KEYGEN"
        assert res_0["level"] == "error"
        loc = res_0["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "backend/crypto.py"
        assert loc["region"]["startLine"] == 10
        assert loc["region"]["endLine"] == 12
        assert "rsa.generate_private_key" in loc["region"]["snippet"]["text"]

        # Validate HNDL advisory inclusion
        assert "Harvest-Now-Decrypt-Later" in res_0["message"]["text"]
        assert res_0["properties"]["hndl"] is True


class TestSarifApiAndCliIntegration:
    """Tests the SARIF export API endpoint and CLI flag."""

    def test_api_export_sarif_demo_scan(self):
        response = client.get("/api/v1/export/demo-workspace-01/sarif")
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "2.1.0"
        assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert len(data["runs"][0]["results"]) >= 3
        assert "Content-Disposition" in response.headers
        assert "Keynova_SARIF_demo-wor.sarif" in response.headers["Content-Disposition"]

    def test_api_export_sarif_not_found(self):
        response = client.get("/api/v1/export/nonexistent-scan-id/sarif")
        assert response.status_code == 404

    def test_cli_export_sarif_flag(self, tmp_path):
        sarif_out = tmp_path / "cli_results.sarif"
        vulnerable_fixture = Path("test-fixtures/vulnerable_payment_suite").resolve()

        # Run CLI with --export-sarif flag; expect exit code 1 due to policy failure
        with pytest.raises(SystemExit) as exc_info:
            run_cli([str(vulnerable_fixture), "--export-sarif", str(sarif_out)])

        assert exc_info.value.code == 1
        assert sarif_out.exists()

        content = json.loads(sarif_out.read_text(encoding="utf-8"))
        assert content["version"] == "2.1.0"
        assert len(content["runs"][0]["results"]) >= 3
