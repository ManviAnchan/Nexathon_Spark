"""
Keynova SARIF 2.1.0 Exporter (OASIS Static Analysis Results Interchange Format)
Maps Keynova cryptographic and post-quantum findings into GitHub Code Scanning compatible SARIF reports.
"""

from typing import List, Dict, Any, Optional

SEVERITY_MAP = {
    "critical": {"level": "error", "security_severity": "9.5"},
    "high": {"level": "error", "security_severity": "8.0"},
    "medium": {"level": "warning", "security_severity": "5.5"},
    "low": {"level": "warning", "security_severity": "2.5"},
    "quantum_safe": {"level": "note", "security_severity": "0.0"}
}

HNDL_ADVISORY = (
    "[HNDL Advisory] Harvest-Now-Decrypt-Later risk: Adversaries can capture and store "
    "this encrypted traffic today to decrypt retroactively once cryptanalytically relevant "
    "quantum computers (CRQCs) become operational. Migrate immediately to NIST FIPS 203/204 algorithms."
)

RULE_TEMPLATES = {
    "PYTHON_RSA_KEYGEN": {
        "name": "VulnerableRsaKeyGeneration",
        "shortDescription": "RSA key generation is vulnerable to Shor's quantum algorithm.",
        "help": "Replace RSA asymmetric key establishment with NIST FIPS 203 ML-KEM or hybrid post-quantum schemes."
    },
    "PYTHON_ECC_KEYGEN": {
        "name": "VulnerableEccKeyGeneration",
        "shortDescription": "Elliptic Curve cryptography (ECC) is vulnerable to Shor's quantum algorithm.",
        "help": "Migrate ECC curves (SECP256R1, Ed25519) to NIST FIPS 204 ML-DSA or State-Management Hash-Based Signatures (LMS/XMSS)."
    },
    "PYTHON_MD5_HASH": {
        "name": "BrokenMd5Hashing",
        "shortDescription": "MD5 hash function is cryptographically broken and prone to collision attacks.",
        "help": "Migrate to SHA-256, SHA-3, or BLAKE2."
    },
    "PYTHON_SHA1_HASH": {
        "name": "BrokenSha1Hashing",
        "shortDescription": "SHA-1 hash function is broken against collision attacks.",
        "help": "Upgrade SHA-1 hashes to SHA-256, SHA-384, or SHA-512."
    },
    "DEP_LEGACY_CRYPTO": {
        "name": "LegacyCryptographicDependency",
        "shortDescription": "Manifest depends on outdated or non-quantum-resistant cryptographic libraries.",
        "help": "Upgrade cryptographic dependencies to liboqs-python or modern cryptographic libraries with PQC support."
    }
}

def generate_sarif_report(
    findings: List[Dict[str, Any]],
    project_name: str = "Keynova Cryptographic Project",
    scan_id: str = "scan-default"
) -> Dict[str, Any]:
    """
    Emits an OASIS SARIF v2.1.0 compliant dictionary mapping Keynova cryptographic
    findings to GitHub Code Scanning rules and results.
    """
    rules_dict: Dict[str, Dict[str, Any]] = {}
    rule_ids_order: List[str] = []
    results: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = f.get("rule_id") or f"KEYNOVA_{f.get('algorithm', 'UNKNOWN').upper().replace('-', '_')}"
        severity = f.get("severity", "low").lower()
        sev_meta = SEVERITY_MAP.get(severity, {"level": "warning", "security_severity": "5.0"})
        level = sev_meta["level"]
        sec_sev = sev_meta["security_severity"]
        is_hndl = bool(f.get("hndl", False))
        algo = f.get("algorithm", "Unknown Algorithm")
        usage = f.get("usage", "cryptographic operations")
        evidence = f.get("evidence", "")

        # Register rule if not already present
        if rule_id not in rules_dict:
            rule_template = RULE_TEMPLATES.get(rule_id, {})
            name = rule_template.get("name", rule_id.replace("_", " ").title().replace(" ", ""))
            short_desc = rule_template.get("shortDescription", f"Cryptographic finding: {algo} used for {usage}.")
            help_msg = rule_template.get("help", "Review cryptographic algorithm and transition to NIST Post-Quantum standards.")
            
            if is_hndl:
                help_msg = f"{help_msg}\n\n{HNDL_ADVISORY}"

            rule_entry = {
                "id": rule_id,
                "name": name,
                "shortDescription": {
                    "text": short_desc
                },
                "fullDescription": {
                    "text": evidence or short_desc
                },
                "defaultConfiguration": {
                    "level": level
                },
                "help": {
                    "text": help_msg,
                    "markdown": f"### Remediation Guidance\n\n{help_msg}"
                },
                "properties": {
                    "tags": ["security", "cryptography", "pqc"] + (["hndl", "quantum-vulnerable"] if is_hndl else []),
                    "security-severity": sec_sev,
                    "precision": "high"
                }
            }
            rules_dict[rule_id] = rule_entry
            rule_ids_order.append(rule_id)

        rule_index = rule_ids_order.index(rule_id)

        # Build message
        msg_parts = [f"Cryptographic finding: {algo} in {usage}."]
        if evidence:
            msg_parts.append(evidence)
        if is_hndl:
            msg_parts.append(HNDL_ADVISORY)
        full_message = " ".join(msg_parts)

        line_start = max(1, int(f.get("line_start", 1) or 1))
        line_end = max(line_start, int(f.get("line_end", line_start) or line_start))
        file_path = f.get("file_path", "unknown")
        snippet = f.get("code_snippet", "")

        result_obj: Dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": level,
            "message": {
                "text": full_message
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": line_start,
                            "endLine": line_end,
                            "snippet": {
                                "text": snippet
                            }
                        }
                    }
                }
            ],
            "properties": {
                "algorithm": algo,
                "usage": usage,
                "severity": severity,
                "quantum_status": f.get("quantum_status", "quantum_vulnerable"),
                "hndl": is_hndl,
                "fingerprint": f.get("fingerprint", "")
            }
        }
        results.append(result_obj)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Keynova",
                        "organization": "Keynova Security",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/ManviAnchan/Nexathon_Spark",
                        "rules": [rules_dict[rid] for rid in rule_ids_order]
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "arguments": [f"--scan-id={scan_id}", f"--project={project_name}"]
                    }
                ],
                "results": results
            }
        ]
    }
    return sarif_doc
