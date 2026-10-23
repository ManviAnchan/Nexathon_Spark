"""
Unit, integration, and structural validation test suite for Keynova's CycloneDX 1.6
Cryptographic Bill of Materials (CBOM) exporter (cbom.py).

Verifies CycloneDX 1.6 top-level envelope, metadata, serial number format,
component hierarchy, cryptoProperties, algorithmProperties, valid assetType and
primitive enums, defensible security strengths, JSON serialization, and live fixture
exports against vulnerable and remediated payment suites.

FORMAL VALIDATION ENGINE LIMITATION NOTICE:
A formal third-party Draft-07 JSON Schema validation engine (such as the Python
'jsonschema' or 'fastjsonschema' library, or Node 'ajv') is not installed in the
execution environment. In accordance with strict environment constraints, external
dependencies were neither installed nor added to requirements.txt.
In its place, this suite conducts rigorous, exhaustive structural and syntactic
verification directly against the official CycloneDX 1.6 JSON Schema definition
(bom-1.6.schema.json), checking envelope requirements, permitted properties,
forbidden custom fields (additionalProperties: False), and enum restrictions.
"""

import sys
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import pytest

# Ensure backend root is on sys.path for direct script execution and diverse test runners
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from keynova.services.exporters.cbom import (
    generate_cyclonedx_cbom,
    VALID_CYCLONEDX_ASSET_TYPES,
    VALID_CYCLONEDX_PRIMITIVES,
    _map_asset_type,
    _map_algorithm_primitive,
    _calculate_security_strengths,
)
from keynova.services.scanner.python_ast import scan_python_file
from keynova.services.scanner.manifests import scan_manifest_file

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "test-fixtures"
if not FIXTURES_DIR.exists():
    FIXTURES_DIR = Path(__file__).resolve().parent.parent / "test-fixtures"
VULN_FIXTURE_DIR = FIXTURES_DIR / "vulnerable_payment_suite"
REMED_FIXTURE_DIR = FIXTURES_DIR / "remediated_payment_suite"

VALID_CYCLONEDX_COMPONENT_TYPES = {
    "application", "framework", "library", "container", "platform",
    "operating-system", "device", "device-driver", "firmware", "file",
    "machine-learning-model", "data", "cryptographic-asset",
}

ALLOWED_CRYPTO_PROPERTIES = {
    "assetType",
    "algorithmProperties",
    "certificateProperties",
    "relatedCryptoMaterialProperties",
    "protocolProperties",
    "oid",
}

ALLOWED_ALGORITHM_PROPERTIES = {
    "primitive",
    "parameterSetIdentifier",
    "curve",
    "executionEnvironment",
    "implementationPlatform",
    "certificationLevel",
    "mode",
    "padding",
    "cryptoFunctions",
    "classicalSecurityLevel",
    "nistQuantumSecurityLevel",
}

ALLOWED_CERTIFICATE_PROPERTIES = {
    "subjectName",
    "issuerName",
    "notValidBefore",
    "notValidAfter",
    "signatureAlgorithmRef",
    "subjectPublicKeyRef",
    "certificateFormat",
    "certificateExtension",
}

ALLOWED_PROTOCOL_PROPERTIES = {
    "type",
    "version",
    "cipherSuites",
    "ikev2TransformTypes",
    "cryptoRefArray",
}

ALLOWED_RELATED_MATERIAL_PROPERTIES = {
    "type",
    "id",
    "state",
    "algorithmRef",
    "creationDate",
    "activationDate",
    "updateDate",
    "expirationDate",
    "value",
    "size",
    "format",
    "securedBy",
}

ALLOWED_ROOT_PROPERTIES = {
    "$schema", "bomFormat", "specVersion", "serialNumber", "version",
    "metadata", "components", "services", "externalReferences", "dependencies",
    "compositions", "vulnerabilities", "annotations", "formulation",
    "declarations", "definitions", "properties", "signature",
}

ALLOWED_METADATA_PROPERTIES = {
    "timestamp", "lifecycles", "tools", "authors", "component",
    "manufacture", "supplier", "licenses", "properties",
}

ALLOWED_COMPONENT_PROPERTIES = {
    "type", "mime-type", "bom-ref", "supplier", "manufacturer",
    "authors", "author", "publisher", "group", "name", "version",
    "description", "scope", "hashes", "licenses", "copyright", "cpe",
    "purl", "omniborId", "swhid", "swid", "modified", "pedigree",
    "externalReferences", "components", "evidence", "releaseNotes",
    "modelCard", "data", "cryptoProperties", "properties", "tags", "signature",
}

ALLOWED_EVIDENCE_PROPERTIES = {
    "identity", "occurrences", "callstack", "licenses", "copyright",
}

ALLOWED_OCCURRENCE_PROPERTIES = {
    "bom-ref", "location", "line", "offset", "symbol", "additionalContext",
}

VALID_PROTOCOL_TYPES = {
    "tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"
}

VALID_RELATED_MATERIAL_TYPES = {
    'private-key', 'public-key', 'secret-key', 'key', 'ciphertext',
    'signature', 'digest', 'initialization-vector', 'nonce', 'seed',
    'salt', 'shared-secret', 'tag', 'additional-data', 'password',
    'credential', 'token', 'other', 'unknown'
}

VALID_KEY_STATES = {
    'pre-activation', 'active', 'suspended', 'deactivated', 'compromised', 'destroyed'
}

VALID_MODES = {'cbc', 'ecb', 'ccm', 'gcm', 'cfb', 'ofb', 'ctr', 'other', 'unknown'}
VALID_PADDINGS = {'pkcs5', 'pkcs7', 'pkcs1v15', 'oaep', 'raw', 'other', 'unknown'}
VALID_EXECUTION_ENVIRONMENTS = {
    'software-plain-ram', 'software-encrypted-ram', 'software-tee', 'hardware', 'other', 'unknown'
}
VALID_IMPLEMENTATION_PLATFORMS = {
    'generic', 'x86_32', 'x86_64', 'armv7-a', 'armv7-m', 'armv8-a',
    'armv8-m', 'armv9-a', 'armv9-m', 's390x', 'ppc64', 'ppc64le', 'other', 'unknown'
}


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


def _validate_cbom_structural_conformance(cbom: Dict[str, Any]):
    """
    Detailed programmatic structural validator that inspects exported CBOM structures
    against known schema constraints from the official CycloneDX 1.6 JSON Schema
    (https://cyclonedx.org/schema/bom-1.6.schema.json).

    NOTE & EXPLICIT LIMITATION:
    This is an in-tree programmatic structural conformance validator enforcing
    property allowlists (additionalProperties: false), data types, string regexes,
    enum memberships, and numeric bounds derived directly from bom-1.6.schema.json.
    It is NOT a formal third-party JSON Schema engine (such as jsonschema)
    and does not perform automated metaschema / Draft-07 reference resolution.
    """
    # 1. Root envelope constraints
    unsupported_root = set(cbom.keys()) - ALLOWED_ROOT_PROPERTIES
    assert not unsupported_root, f"Disallowed root properties in CBOM: {unsupported_root}"

    assert cbom.get("bomFormat") == "CycloneDX", "bomFormat must be 'CycloneDX'"
    assert cbom.get("specVersion") == "1.6", "specVersion must be '1.6'"
    assert isinstance(cbom.get("version"), int) and cbom["version"] >= 1, "version must be an integer >= 1"
    assert "serialNumber" in cbom, "serialNumber is required"
    uuid_pattern = r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    assert re.match(uuid_pattern, cbom["serialNumber"]), f"Invalid serialNumber: {cbom['serialNumber']}"

    # 2. Metadata constraints
    assert "metadata" in cbom, "metadata is required"
    meta = cbom["metadata"]
    unsupported_meta = set(meta.keys()) - ALLOWED_METADATA_PROPERTIES
    assert not unsupported_meta, f"Disallowed metadata properties: {unsupported_meta}"

    assert "timestamp" in meta, "metadata.timestamp is required"
    assert "tools" in meta, "metadata.tools is required"
    assert "component" in meta, "metadata.component is required"

    if isinstance(meta["tools"], dict):
        assert set(meta["tools"].keys()).issubset({"components", "services"})
        if "components" in meta["tools"]:
            for tool_comp in meta["tools"]["components"]:
                assert "type" in tool_comp and "name" in tool_comp

    if "properties" in meta:
        for p in meta["properties"]:
            assert "name" in p and isinstance(p["name"], str)
            if "value" in p:
                assert isinstance(p["value"], str)

    # 3. Components constraints
    assert "components" in cbom, "components array is required"
    assert isinstance(cbom["components"], list), "components must be a list"

    seen_refs = set()
    for c in cbom["components"]:
        unsupported_comp = set(c.keys()) - ALLOWED_COMPONENT_PROPERTIES
        assert not unsupported_comp, f"Disallowed component properties: {unsupported_comp}"

        assert c.get("type") in VALID_CYCLONEDX_COMPONENT_TYPES, f"Invalid component type: {c.get('type')}"
        assert "bom-ref" in c, "bom-ref is required on component"
        assert isinstance(c["bom-ref"], str) and len(c["bom-ref"]) >= 1, "bom-ref must be non-empty string"
        assert c["bom-ref"] not in seen_refs, f"Duplicate bom-ref found: {c['bom-ref']}"
        seen_refs.add(c["bom-ref"])

        assert "name" in c and isinstance(c["name"], str), "Component name must be a string"
        assert "cryptoProperties" in c, "cryptoProperties is required for cryptographic-asset"

        # 4. CryptoProperties constraints
        cp = c["cryptoProperties"]
        assert "assetType" in cp, "assetType is required in cryptoProperties"
        assert cp["assetType"] in VALID_CYCLONEDX_ASSET_TYPES, f"Invalid assetType: {cp.get('assetType')}"
        unsupported_cp = set(cp.keys()) - ALLOWED_CRYPTO_PROPERTIES
        assert not unsupported_cp, f"Forbidden fields directly in cryptoProperties: {unsupported_cp}"

        if "algorithmProperties" in cp:
            ap = cp["algorithmProperties"]
            unsupported_ap = set(ap.keys()) - ALLOWED_ALGORITHM_PROPERTIES
            assert not unsupported_ap, f"Forbidden fields in algorithmProperties: {unsupported_ap}"
            assert ap.get("primitive") in VALID_CYCLONEDX_PRIMITIVES, f"Invalid primitive: {ap.get('primitive')}"
            if "parameterSetIdentifier" in ap:
                assert isinstance(ap["parameterSetIdentifier"], str)
            if "curve" in ap:
                assert isinstance(ap["curve"], str)
            if "mode" in ap:
                assert ap["mode"] in VALID_MODES, f"Invalid mode: {ap['mode']}"
            if "padding" in ap:
                assert ap["padding"] in VALID_PADDINGS, f"Invalid padding: {ap['padding']}"
            if "executionEnvironment" in ap:
                assert ap["executionEnvironment"] in VALID_EXECUTION_ENVIRONMENTS
            if "implementationPlatform" in ap:
                assert ap["implementationPlatform"] in VALID_IMPLEMENTATION_PLATFORMS
            if "classicalSecurityLevel" in ap:
                assert isinstance(ap["classicalSecurityLevel"], int) and ap["classicalSecurityLevel"] >= 0
            if "nistQuantumSecurityLevel" in ap:
                assert isinstance(ap["nistQuantumSecurityLevel"], int) and 0 <= ap["nistQuantumSecurityLevel"] <= 6

        if "certificateProperties" in cp:
            cert = cp["certificateProperties"]
            unsupported_cert = set(cert.keys()) - ALLOWED_CERTIFICATE_PROPERTIES
            assert not unsupported_cert, f"Forbidden fields in certificateProperties: {unsupported_cert}"
            if "subjectName" in cert:
                assert isinstance(cert["subjectName"], str)
            if "issuerName" in cert:
                assert isinstance(cert["issuerName"], str)
            if "certificateFormat" in cert:
                assert isinstance(cert["certificateFormat"], str)
            if "certificateExtension" in cert:
                assert isinstance(cert["certificateExtension"], str)
            if "notValidBefore" in cert:
                assert isinstance(cert["notValidBefore"], str)
                assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", cert["notValidBefore"]), f"Invalid notValidBefore date-time: {cert['notValidBefore']}"
            if "notValidAfter" in cert:
                assert isinstance(cert["notValidAfter"], str)
                assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", cert["notValidAfter"]), f"Invalid notValidAfter date-time: {cert['notValidAfter']}"

        if "protocolProperties" in cp:
            prot = cp["protocolProperties"]
            unsupported_prot = set(prot.keys()) - ALLOWED_PROTOCOL_PROPERTIES
            assert not unsupported_prot, f"Forbidden fields in protocolProperties: {unsupported_prot}"
            if "type" in prot:
                assert prot["type"] in VALID_PROTOCOL_TYPES, f"Invalid protocol type: {prot['type']}"
            if "version" in prot:
                assert isinstance(prot["version"], str)

        if "relatedCryptoMaterialProperties" in cp:
            rel = cp["relatedCryptoMaterialProperties"]
            unsupported_rel = set(rel.keys()) - ALLOWED_RELATED_MATERIAL_PROPERTIES
            assert not unsupported_rel, f"Forbidden fields in relatedCryptoMaterialProperties: {unsupported_rel}"
            if "type" in rel:
                assert rel["type"] in VALID_RELATED_MATERIAL_TYPES, f"Invalid related material type: {rel['type']}"
            if "state" in rel:
                assert rel["state"] in VALID_KEY_STATES, f"Invalid key state: {rel['state']}"
            if "size" in rel:
                assert isinstance(rel["size"], int) and rel["size"] >= 0

        # 5. Component properties (Keynova metadata)
        if "properties" in c:
            for p in c["properties"]:
                assert "name" in p and isinstance(p["name"], str)
                assert "value" in p and isinstance(p["value"], str)

        # 6. Component evidence (source code occurrences)
        if "evidence" in c:
            ev = c["evidence"]
            unsupported_ev = set(ev.keys()) - ALLOWED_EVIDENCE_PROPERTIES
            assert not unsupported_ev, f"Forbidden fields in evidence: {unsupported_ev}"
            if "occurrences" in ev:
                assert isinstance(ev["occurrences"], list)
                for occ in ev["occurrences"]:
                    unsupported_occ = set(occ.keys()) - ALLOWED_OCCURRENCE_PROPERTIES
                    assert not unsupported_occ, f"Forbidden fields in occurrence: {unsupported_occ}"
                    assert "location" in occ and isinstance(occ["location"], str)
                    if "line" in occ:
                        assert isinstance(occ["line"], int) and occ["line"] >= 0
                    if "offset" in occ:
                        assert isinstance(occ["offset"], int) and occ["offset"] >= 0


# ============================================================================
# 1. CYCLONEDX 1.6 ENVELOPE, METADATA & SERIAL NUMBER TESTS
# ============================================================================

class TestCycloneDxEnvelopeAndMetadata:
    """Verifies CycloneDX 1.6 envelope, serial number, and metadata compliance."""

    def test_top_level_cyclonedx_1_6_format(self):
        """Verifies bomFormat, specVersion, and version conform to CycloneDX 1.6."""
        cbom = generate_cyclonedx_cbom(
            project_name="Payment Gateway",
            scan_id="scan-abc12345",
            findings=[],
            readiness_score=85,
        )
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert cbom["version"] == 1
        assert "components" in cbom
        assert "metadata" in cbom

    def test_serial_number_valid_urn_uuid_format(self):
        """Verifies serialNumber matches the URN UUID regex specification."""
        cbom = generate_cyclonedx_cbom(
            project_name="Payment Gateway",
            scan_id="scan-abc12345",
            findings=[],
            readiness_score=85,
        )
        serial = cbom.get("serialNumber", "")
        uuid_pattern = r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        assert re.match(uuid_pattern, serial), f"Invalid serialNumber format: {serial}"

    def test_metadata_structure_and_tool_info(self):
        """Verifies metadata timestamp, tools component, target component, and custom properties."""
        cbom = generate_cyclonedx_cbom(
            project_name="Payment Gateway Core",
            scan_id="scan-xyz98765",
            findings=[],
            readiness_score=92,
        )
        meta = cbom["metadata"]
        assert "timestamp" in meta
        assert "T" in meta["timestamp"]

        tool_comp = meta["tools"]["components"][0]
        assert tool_comp["type"] == "application"
        assert tool_comp["name"] == "Keynova Post-Quantum Readiness Engine"
        assert tool_comp["version"] == "1.0.0"

        target_comp = meta["component"]
        assert target_comp["type"] == "application"
        assert target_comp["name"] == "Payment Gateway Core"
        assert target_comp["version"] == "scan-scan-xyz"

        props = {p["name"]: p["value"] for p in meta["properties"]}
        assert props.get("keynova:readiness_score") == "92"
        assert props.get("keynova:cbom_version") == "1.6"


# ============================================================================
# 2. CRYPTOGRAPHIC ASSET COMPONENTS & CRYPTOPROPERTIES TESTS
# ============================================================================

class TestCycloneDxCryptoComponents:
    """Verifies cryptographic-asset components, cryptoProperties, and schema enums."""

    def test_component_type_and_unique_bom_ref(self):
        """Each component must have type 'cryptographic-asset' and a unique bom-ref."""
        sample_findings = [
            {"id": "find-1", "algorithm": "RSA", "severity": "critical", "hndl": True},
            {"id": "find-2", "algorithm": "ECC-SECP256R1", "severity": "high", "hndl": True},
            {"id": "find-3", "algorithm": "MD5", "severity": "low", "hndl": False},
        ]
        cbom = generate_cyclonedx_cbom("Test App", "scan-1", sample_findings, 50)
        components = cbom["components"]
        assert len(components) == 3

        bom_refs = [c["bom-ref"] for c in components]
        assert len(bom_refs) == len(set(bom_refs)), "All bom-refs must be strictly unique"

        for c in components:
            assert c["type"] == "cryptographic-asset"
            assert c["bom-ref"].startswith("crypto-asset-")
            assert "cryptoProperties" in c
            assert "properties" in c

    def test_valid_asset_type_enum_compliance(self):
        """
        cryptoProperties.assetType must strictly be one of:
        'algorithm', 'certificate', 'protocol', 'related-crypto-material'.
        Internal values like 'source_code' or 'manifest' must not leak into the CBOM.
        """
        diverse_findings = [
            {"id": "1", "asset_type": "source_code", "algorithm": "RSA"},
            {"id": "2", "asset_type": "manifest", "algorithm": "PyCryptodome"},
            {"id": "3", "asset_type": "certificate", "algorithm": "X.509-RSA"},
            {"id": "4", "asset_type": "tls", "algorithm": "TLSv1.2"},
            {"id": "5", "asset_type": "key", "algorithm": "AES-Key"},
            {"id": "6", "asset_type": None, "algorithm": "Unknown"},
        ]
        cbom = generate_cyclonedx_cbom("Test App", "scan-1", diverse_findings, 60)
        for c in cbom["components"]:
            cp = c["cryptoProperties"]
            asset_type = cp["assetType"]
            assert asset_type in VALID_CYCLONEDX_ASSET_TYPES, (
                f"Invalid assetType '{asset_type}' emitted; must be in {VALID_CYCLONEDX_ASSET_TYPES}"
            )
            unsupported_fields = set(cp.keys()) - ALLOWED_CRYPTO_PROPERTIES
            assert not unsupported_fields, f"Unsupported fields in cryptoProperties: {unsupported_fields}"

    def test_cryptoproperties_field_structure_and_location_preservation(self):
        """
        Verifies:
        1. classicalSecurityLevel and nistQuantumSecurityLevel are inside algorithmProperties.
        2. No unsupported custom fields exist directly on cryptoProperties.
        3. Quantum vulnerability, HNDL risk, and source locations are preserved in component.properties and component.evidence.
        4. Defensible security strengths (RSA 2048 -> 112 bits, ML-KEM-768 -> 192 bits).
        """
        findings = [
            {
                "id": "rsa-1",
                "algorithm": "RSA",
                "key_size": 2048,
                "quantum_status": "quantum_vulnerable",
                "hndl": True,
                "usage": "key_generation",
                "file_path": "crypto.py",
                "line_start": 10,
                "line_end": 15,
                "code_snippet": "rsa.generate_private_key()",
            },
            {
                "id": "kem-1",
                "algorithm": "ML-KEM-768",
                "key_size": 1184,
                "quantum_status": "quantum_safe",
                "hndl": False,
                "usage": "kem",
                "file_path": "pq_crypto.py",
                "line_start": 20,
                "line_end": 25,
            },
        ]
        cbom = generate_cyclonedx_cbom("App", "scan-1", findings, 70)
        c_rsa = cbom["components"][0]
        c_kem = cbom["components"][1]

        cp_rsa = c_rsa["cryptoProperties"]
        cp_kem = c_kem["cryptoProperties"]

        for forbidden in ["algorithm", "classicalSecurityLevel", "nistQuantumSecurityLevel",
                          "quantumVulnerable", "harvestNowDecryptLaterRisk", "location"]:
            assert forbidden not in cp_rsa, f"Forbidden field '{forbidden}' found directly in cryptoProperties"
            assert forbidden not in cp_kem, f"Forbidden field '{forbidden}' found directly in cryptoProperties"

        assert cp_rsa["assetType"] == "algorithm"
        rsa_alg_props = cp_rsa["algorithmProperties"]
        assert rsa_alg_props["nistQuantumSecurityLevel"] == 0
        assert rsa_alg_props["classicalSecurityLevel"] == 112
        assert rsa_alg_props["parameterSetIdentifier"] == "2048"

        assert cp_kem["assetType"] == "algorithm"
        kem_alg_props = cp_kem["algorithmProperties"]
        assert kem_alg_props["nistQuantumSecurityLevel"] == 3
        assert kem_alg_props["classicalSecurityLevel"] == 192
        assert kem_alg_props["parameterSetIdentifier"] == "ML-KEM-768"

        rsa_props = {p["name"]: p["value"] for p in c_rsa["properties"]}
        assert rsa_props["keynova:quantum_vulnerable"] == "true"
        assert rsa_props["keynova:hndl"] == "true"
        assert rsa_props["keynova:quantum_status"] == "quantum_vulnerable"
        assert rsa_props["keynova:file_path"] == "crypto.py"
        assert rsa_props["keynova:line_start"] == "10"
        assert rsa_props["keynova:line_end"] == "15"
        assert rsa_props["keynova:key_size"] == "2048"

        kem_props = {p["name"]: p["value"] for p in c_kem["properties"]}
        assert kem_props["keynova:quantum_vulnerable"] == "false"
        assert kem_props["keynova:hndl"] == "false"
        assert kem_props["keynova:quantum_status"] == "quantum_safe"

        assert "evidence" in c_rsa
        occurrences = c_rsa["evidence"]["occurrences"]
        assert len(occurrences) == 1
        assert occurrences[0]["location"] == "crypto.py"
        assert occurrences[0]["line"] == 10
        assert occurrences[0]["additionalContext"] == "rsa.generate_private_key()"

    def test_algorithm_properties_primitive_mapping(self):
        """Verifies primitive category mapping under algorithmProperties uses official schema enums."""
        findings = [
            {"id": "1", "algorithm": "RSA", "usage": "key_generation", "key_size": 2048},
            {"id": "2", "algorithm": "ECC-SECP256R1", "usage": "token_signing", "key_size": 256},
            {"id": "3", "algorithm": "MD5", "usage": "password_hashing", "key_size": 128},
            {"id": "4", "algorithm": "ML-KEM-768", "usage": "kem", "key_size": 768},
        ]
        cbom = generate_cyclonedx_cbom("App", "scan-1", findings, 80)
        comps = {c["name"]: c["cryptoProperties"]["algorithmProperties"] for c in cbom["components"]}

        assert comps["RSA"]["primitive"] == "pke"
        assert comps["RSA"]["parameterSetIdentifier"] == "2048"

        assert comps["ECC-SECP256R1"]["primitive"] == "signature"
        assert comps["ECC-SECP256R1"]["curve"] == "secp256r1"

        assert comps["MD5"]["primitive"] == "hash"
        assert comps["MD5"]["primitive"] in VALID_CYCLONEDX_PRIMITIVES
        assert comps["MD5"]["parameterSetIdentifier"] == "128"

        assert comps["ML-KEM-768"]["primitive"] == "kem"
        assert comps["ML-KEM-768"]["primitive"] in VALID_CYCLONEDX_PRIMITIVES

    def test_primitive_mappings_exhaustive_and_regressions(self):
        """
        Exhaustively verifies _map_algorithm_primitive() against all official schema primitive values
        and ensures ambiguous/unknown algorithms do not receive misleading classifications.
        """
        test_cases = [
            # 1. Hashes must map to 'hash' (not 'digest')
            ("MD5", "password_hashing", "hash"),
            ("SHA-256", "hashing", "hash"),
            ("SHA-512", "digest", "hash"),
            ("BLAKE2b", "hash", "hash"),
            ("SHA-1", "checksum", "hash"),

            # 2. HMAC must map to 'mac' (not 'hash')
            ("HMAC-SHA256", "mac", "mac"),
            ("HMAC-SHA512", "authentication", "mac"),
            ("HMAC-MD5", "token_mac", "mac"),
            ("AES-CMAC", "mac", "mac"),

            # 3. KEM must map to 'kem'
            ("ML-KEM-768", "kem", "kem"),
            ("Kyber-512", "encapsulate", "kem"),
            ("ML-KEM-1024", "key_encapsulation", "kem"),

            # 4. Signatures must map to 'signature'
            ("ML-DSA-65", "token_signing", "signature"),
            ("ML-DSA-44", "signing", "signature"),
            ("ECDSA", "token_signing", "signature"),
            ("Ed25519", "sign", "signature"),
            ("Ed448", "signature", "signature"),
            ("FALCON-512", "signing", "signature"),

            # 5. Authenticated Encryption must map to 'ae' (not merely 'block-cipher')
            ("AES-GCM", "encryption", "ae"),
            ("AES-256-GCM", "encryption", "ae"),
            ("AES", "authenticated_encryption", "ae"),
            ("AES", "gcm", "ae"),
            ("ChaCha20-Poly1305", "encryption", "ae"),
            ("AES-CCM", "encryption", "ae"),

            # 6. Block Ciphers
            ("AES-128", "encrypt", "block-cipher"),
            ("AES-256", "encryption", "block-cipher"),
            ("DES", "encryption", "block-cipher"),
            ("3DES", "encrypt", "block-cipher"),
            ("Blowfish", "encryption", "block-cipher"),

            # 7. Stream Ciphers
            ("RC4", "stream_cipher", "stream-cipher"),
            ("ChaCha20", "encryption", "stream-cipher"),
            ("Salsa20", "encryption", "stream-cipher"),

            # 8. Key Agreement
            ("ECDH", "key_agree", "key-agree"),
            ("Diffie-Hellman", "key_exchange", "key-agree"),
            ("X25519", "key_agreement", "key-agree"),

            # 9. Public Key Encryption
            ("RSA", "key_generation", "pke"),
            ("RSA", "encrypt", "pke"),
            ("ElGamal", "pke", "pke"),

            # 10. Key Derivation Functions
            ("PBKDF2", "kdf", "kdf"),
            ("HKDF", "key_derivation", "kdf"),
            ("scrypt", "kdf", "kdf"),

            # 11. Random Bit Generators
            ("CTR_DRBG", "random", "drbg"),

            # 12. Multi-algorithm manifests
            ("DES/RSA/RC4", "dependency", "combiner"),

            # 13. Ambiguous or unknown algorithms must NOT receive misleading classifications
            ("Unknown", "encryption", "unknown"),
            ("Unknown", "key_generation", "unknown"),
            ("CustomAlg", "encryption", "other"),
            ("Legacy Ciphers", "dependency", "other"),
            ("ArbitraryName", "generic_use", "other"),
            ("", "", "unknown"),
            (None, None, "unknown"),
        ]
        for alg, usage, expected_primitive in test_cases:
            primitive = _map_algorithm_primitive(alg, usage)
            assert primitive == expected_primitive, (
                f"Primitive for ({alg}, {usage}) should be '{expected_primitive}', got '{primitive}'"
            )
            assert primitive in VALID_CYCLONEDX_PRIMITIVES, (
                f"Primitive '{primitive}' is not in valid CycloneDX 1.6 primitive enum"
            )

    def test_quantum_security_level_not_assigned_to_arbitrary_quantum_safe_algorithm(self):
        """
        CRITICAL: Never assign nistQuantumSecurityLevel = 3 to an arbitrary algorithm
        simply because it is marked quantum-safe.
        Only assign when reliably identified and mapped to documented categories.
        """
        arbitrary_algs = [
            "CustomPQC",
            "QuantumSafeScheme",
            "PostQuantumWrapper",
            "ExperimentalLattice",
            "Unknown",
        ]
        for alg in arbitrary_algs:
            sec_level, q_level = _calculate_security_strengths(alg, key_size=None, is_quantum_vulnerable=False)
            assert q_level is None, (
                f"Arbitrary algorithm '{alg}' marked quantum-safe must NOT receive an invented quantum level, got {q_level}"
            )
            assert sec_level is None, (
                f"Arbitrary algorithm '{alg}' must NOT receive an invented classical security level, got {sec_level}"
            )

    def test_ml_kem_and_ml_dsa_variants_identified_by_name_not_byte_lengths(self):
        """
        CRITICAL: Identify ML-KEM and ML-DSA variants using their algorithm names
        rather than inferring their parameter sets from public-key byte lengths.
        Incomplete names without variant must return None.
        """
        # Documented variants correctly mapped from names
        sec_level, q_level = _calculate_security_strengths("ML-KEM-512", key_size=None, is_quantum_vulnerable=False)
        assert sec_level == 128 and q_level == 1

        sec_level, q_level = _calculate_security_strengths("ML-KEM-768", key_size=1184, is_quantum_vulnerable=False)
        assert sec_level == 192 and q_level == 3

        sec_level, q_level = _calculate_security_strengths("ML-KEM-1024", key_size=None, is_quantum_vulnerable=False)
        assert sec_level == 256 and q_level == 5

        sec_level, q_level = _calculate_security_strengths("ML-DSA-44", key_size=None, is_quantum_vulnerable=False)
        assert sec_level == 128 and q_level == 2

        sec_level, q_level = _calculate_security_strengths("ML-DSA-65", key_size=None, is_quantum_vulnerable=False)
        assert sec_level == 192 and q_level == 3

        sec_level, q_level = _calculate_security_strengths("ML-DSA-87", key_size=None, is_quantum_vulnerable=False)
        assert sec_level == 256 and q_level == 5

        # Incomplete / unparameterized names must NOT infer variant from byte lengths
        sec_level, q_level = _calculate_security_strengths("ML-KEM", key_size=1184, is_quantum_vulnerable=False)
        assert sec_level is None, "Incomplete name 'ML-KEM' must not infer security strength from byte length 1184"
        assert q_level is None, "Incomplete name 'ML-KEM' must not infer quantum category from byte length 1184"

        sec_level, q_level = _calculate_security_strengths("Kyber", key_size=1184, is_quantum_vulnerable=False)
        assert sec_level is None
        assert q_level is None

        sec_level, q_level = _calculate_security_strengths("ML-DSA", key_size=1952, is_quantum_vulnerable=False)
        assert sec_level is None
        assert q_level is None

    def test_misleading_and_substandard_key_size_inputs(self):
        """
        Verifies that misleading, negative, or invalid key-size inputs do not corrupt
        security strength calculations, and key_size is not equated with classical security.
        """
        # Unknown algorithm with key_size=2048: must NOT invent 112 or 2048
        sec_level, q_level = _calculate_security_strengths("Unknown", key_size=2048, is_quantum_vulnerable=True)
        assert sec_level is None
        assert q_level is None

        # RSA with negative key size: must not invent strength
        sec_level, q_level = _calculate_security_strengths("RSA", key_size=-5, is_quantum_vulnerable=True)
        assert sec_level is None
        assert q_level == 0

        # RSA with non-numeric key size
        sec_level, q_level = _calculate_security_strengths("RSA", key_size="invalid", is_quantum_vulnerable=True)
        assert sec_level is None
        assert q_level == 0

        # AES with non-standard key size (e.g. 500 bits): must not invent strength
        sec_level, q_level = _calculate_security_strengths("AES", key_size=500, is_quantum_vulnerable=True)
        assert sec_level is None
        assert q_level == 0

        # ECC-SECP256R1 with misleading key_size 2048: algorithm curve is SECP256R1 -> 128 bits
        sec_level, q_level = _calculate_security_strengths("ECC-SECP256R1", key_size=2048, is_quantum_vulnerable=True)
        assert sec_level == 128
        assert q_level == 0

    def test_broken_and_composite_algorithms_do_not_invent_strengths(self):
        """
        Broken algorithms (MD5, SHA-1), composite dependency manifests (DES/RSA/RC4),
        and empty inputs must never have invented classical security strengths or categories.
        """
        broken_cases = ["MD5", "SHA-1", "DES/RSA/RC4", "MD5/SHA1/AES", "", None]
        for alg in broken_cases:
            sec_level, q_level = _calculate_security_strengths(alg, key_size=128, is_quantum_vulnerable=True)
            assert sec_level is None, f"Algorithm '{alg}' must NOT have an invented classicalSecurityLevel"
            assert q_level is None, f"Algorithm '{alg}' must NOT have an invented nistQuantumSecurityLevel"

    def test_hash_algorithms_reviewed_separately_from_encryption_and_signatures(self):
        """
        Verifies that hash algorithms are treated separately from encryption and signatures:
        - Classical security level maps to collision resistance strength (L/2 bits) per NIST SP 800-57 Table 2.
        - Broken hashes (MD5, SHA-1) never receive invented security levels.
        - HMAC is mapped to 'mac' primitive, distinct from 'hash'.
        - Key size is not treated as classical security strength for hashes.
        """
        # SHA-256 collision resistance: 128 bits
        sec_level, q_level = _calculate_security_strengths("SHA-256", key_size=256, is_quantum_vulnerable=False)
        assert sec_level == 128, "SHA-256 classical security level must be 128 bits (collision resistance)"
        assert q_level == 0, "SHA-256 is classical technology (category 0)"

        # SHA-384 collision resistance: 192 bits
        sec_level, q_level = _calculate_security_strengths("SHA-384", key_size=384, is_quantum_vulnerable=False)
        assert sec_level == 192
        assert q_level == 0

        # SHA-512 collision resistance: 256 bits
        sec_level, q_level = _calculate_security_strengths("SHA-512", key_size=512, is_quantum_vulnerable=False)
        assert sec_level == 256
        assert q_level == 0

        # Broken hashes: MD5, SHA-1 must return (None, None)
        assert _calculate_security_strengths("MD5", key_size=128, is_quantum_vulnerable=True) == (None, None)
        assert _calculate_security_strengths("SHA-1", key_size=160, is_quantum_vulnerable=True) == (None, None)

        # Primitive mapping distinction: HMAC vs standard hash
        assert _map_algorithm_primitive("HMAC-SHA256", "mac") == "mac"
        assert _map_algorithm_primitive("SHA-256", "hashing") == "hash"

    def test_certificate_properties_conformance(self):
        """
        Verifies that certificate findings produce valid certificateProperties:
        - assetType == 'certificate'
        - Permitted fields: subjectName, issuerName, certificateFormat, notValidBefore, notValidAfter
        - No illegal properties inside cryptoProperties
        """
        findings = [{
            "id": "cert-test-01",
            "asset_type": "certificate",
            "algorithm": "X.509",
            "subject_name": "CN=test.internal",
            "issuer_name": "CN=Internal Root CA",
            "not_valid_before": "2024-01-01T00:00:00Z",
            "not_valid_after": "2025-01-01T00:00:00Z",
            "certificate_format": "X.509",
            "quantum_status": "quantum_vulnerable",
        }]
        cbom = generate_cyclonedx_cbom("Cert Project", "scan-cert", findings, 70)
        c = cbom["components"][0]
        assert c["cryptoProperties"]["assetType"] == "certificate"
        cert_p = c["cryptoProperties"]["certificateProperties"]
        assert cert_p["subjectName"] == "CN=test.internal"
        assert cert_p["issuerName"] == "CN=Internal Root CA"
        assert cert_p["certificateFormat"] == "X.509"
        assert cert_p["notValidBefore"] == "2024-01-01T00:00:00Z"
        assert cert_p["notValidAfter"] == "2025-01-01T00:00:00Z"
        _validate_cbom_structural_conformance(cbom)

    def test_protocol_properties_conformance(self):
        """
        Verifies that protocol findings produce valid protocolProperties:
        - assetType == 'protocol'
        - type belongs to valid enum: ['tls', 'ssh', 'ipsec', 'ike', 'sstp', 'wpa', 'other', 'unknown']
        - version is valid string
        """
        for proto_name, expected_type, expected_version in [
            ("TLSv1.3", "tls", "1.3"),
            ("TLSv1.2", "tls", "1.2"),
            ("SSH-2.0", "ssh", "2.0"),
            ("IPsec-IKEv2", "ipsec", None),
            ("CustomProto", "other", None),
        ]:
            findings = [{
                "id": f"proto-{proto_name}",
                "asset_type": "protocol",
                "algorithm": proto_name,
                "quantum_status": "quantum_safe" if "1.3" in proto_name else "quantum_vulnerable",
            }]
            cbom = generate_cyclonedx_cbom("Proto Project", "scan-proto", findings, 80)
            c = cbom["components"][0]
            assert c["cryptoProperties"]["assetType"] == "protocol"
            prot_p = c["cryptoProperties"]["protocolProperties"]
            assert prot_p["type"] == expected_type
            if expected_version:
                assert prot_p["version"] == expected_version
            _validate_cbom_structural_conformance(cbom)

    def test_related_crypto_material_properties_conformance(self):
        """
        Verifies that related-crypto-material findings produce valid relatedCryptoMaterialProperties:
        - assetType == 'related-crypto-material'
        - type belongs to valid CycloneDX material enum: ['key', 'secret-key', 'private-key', ...]
        - size is valid non-negative integer
        """
        for raw_asset, expected_type in [
            ("key", "key"),
            ("secret-key", "secret-key"),
            ("private-key", "private-key"),
            ("public-key", "public-key"),
        ]:
            findings = [{
                "id": f"mat-{raw_asset}",
                "asset_type": raw_asset,
                "algorithm": "AES-256",
                "key_size": 256,
                "format": "RAW",
                "quantum_status": "quantum_safe",
            }]
            cbom = generate_cyclonedx_cbom("Material Project", "scan-mat", findings, 90)
            c = cbom["components"][0]
            assert c["cryptoProperties"]["assetType"] == "related-crypto-material"
            rcm_p = c["cryptoProperties"]["relatedCryptoMaterialProperties"]
            assert rcm_p["type"] == expected_type
            assert rcm_p["size"] == 256
            assert rcm_p["format"] == "RAW"
            _validate_cbom_structural_conformance(cbom)

    def test_certificate_properties_mapping_and_safeguards(self):
        """
        Verifies:
        1. Alternative source field mappings (certificate_subject, certificate_issuer,
           validity_start, validity_end, format, extension).
        2. No certificateFormat is invented when absent from source finding.
        3. Malformed validity dates (e.g. non-date strings) are safely omitted without crashing.
        4. Valid ISO-8601 timestamps are preserved.
        """
        # Case A: Alternative field names with valid ISO dates
        findings_alt = [{
            "id": "cert-alt-01",
            "asset_type": "certificate",
            "certificate_subject": "CN=service.internal",
            "certificate_issuer": "CN=Enterprise Root CA",
            "validity_start": "2024-01-01T00:00:00Z",
            "validity_end": "2026-01-01T00:00:00Z",
            "format": "PEM",
            "extension": "crt",
            "quantum_status": "quantum_vulnerable",
        }]
        cbom_a = generate_cyclonedx_cbom("Cert App", "scan-ca", findings_alt, 80)
        c_a = cbom_a["components"][0]
        cp_a = c_a["cryptoProperties"]["certificateProperties"]
        assert cp_a["subjectName"] == "CN=service.internal"
        assert cp_a["issuerName"] == "CN=Enterprise Root CA"
        assert cp_a["certificateFormat"] == "PEM"
        assert cp_a["certificateExtension"] == "crt"
        assert cp_a["notValidBefore"] == "2024-01-01T00:00:00Z"
        assert cp_a["notValidAfter"] == "2026-01-01T00:00:00Z"
        _validate_cbom_structural_conformance(cbom_a)

        # Case B: Missing format and subject - must NOT invent format or subject
        findings_sparse = [{
            "id": "cert-sparse-02",
            "asset_type": "certificate",
            "quantum_status": "quantum_vulnerable",
        }]
        cbom_b = generate_cyclonedx_cbom("Cert App", "scan-cb", findings_sparse, 80)
        c_b = cbom_b["components"][0]
        if "certificateProperties" in c_b["cryptoProperties"]:
            assert "certificateFormat" not in c_b["cryptoProperties"]["certificateProperties"]
            assert "subjectName" not in c_b["cryptoProperties"]["certificateProperties"]
        _validate_cbom_structural_conformance(cbom_b)

        # Case C: Malformed validity dates - must be safely omitted rather than producing invalid date-time strings
        findings_malformed_dates = [{
            "id": "cert-malformed-03",
            "asset_type": "certificate",
            "subject_name": "CN=bad.date.internal",
            "validity_start": "not-a-valid-timestamp",
            "validity_end": 123456,
            "quantum_status": "quantum_vulnerable",
        }]
        cbom_c = generate_cyclonedx_cbom("Cert App", "scan-cc", findings_malformed_dates, 80)
        c_c = cbom_c["components"][0]
        cp_c = c_c["cryptoProperties"]["certificateProperties"]
        assert cp_c["subjectName"] == "CN=bad.date.internal"
        assert "notValidBefore" not in cp_c, "Malformed validity_start must not be exported as invalid date-time"
        assert "notValidAfter" not in cp_c, "Malformed validity_end must not be exported as invalid date-time"
        _validate_cbom_structural_conformance(cbom_c)

    def test_related_crypto_material_properties_safeguards(self):
        """
        Verifies relatedCryptoMaterialProperties constraints:
        - Non-negative integer size; negative, zero, unparseable, and missing sizes are omitted.
        - Material type mapped safely to official CycloneDX enum.
        - State mapped only if valid NIST state.
        """
        test_cases = [
            (256, 256),
            ("512", 512),
            (-128, None),
            (0, None),
            ("unparseable_string", None),
            (None, None),
        ]
        for key_size_in, expected_size in test_cases:
            finding = [{
                "id": "mat-size-test",
                "asset_type": "related-crypto-material",
                "material_type": "secret-key",
                "key_size": key_size_in,
                "quantum_status": "quantum_safe",
            }]
            cbom = generate_cyclonedx_cbom("Material Project", "scan-m", finding, 95)
            rcm = cbom["components"][0]["cryptoProperties"]["relatedCryptoMaterialProperties"]
            if expected_size is not None:
                assert rcm.get("size") == expected_size
            else:
                assert "size" not in rcm, f"Invalid key_size {key_size_in} must be omitted from size property"
            _validate_cbom_structural_conformance(cbom)

        # Material type mappings and state
        type_test_findings = [
            {"id": "t1", "asset_type": "key", "material_type": "symmetric_key", "state": "active"},
            {"id": "t2", "asset_type": "key", "material_type": "private", "state": "compromised"},
            {"id": "t3", "asset_type": "key", "material_type": "public", "state": "destroyed"},
            {"id": "t4", "asset_type": "related-crypto-material", "material_type": "unknown_custom"},
            {"id": "t5", "asset_type": "related-crypto-material", "material_type": None},
        ]
        cbom_types = generate_cyclonedx_cbom("Types Project", "scan-t", type_test_findings, 90)
        comps = cbom_types["components"]
        assert comps[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "secret-key"
        assert comps[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]["state"] == "active"
        assert comps[1]["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "private-key"
        assert comps[1]["cryptoProperties"]["relatedCryptoMaterialProperties"]["state"] == "compromised"
        assert comps[2]["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "public-key"
        assert comps[2]["cryptoProperties"]["relatedCryptoMaterialProperties"]["state"] == "destroyed"
        assert comps[3]["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "other"
        assert comps[4]["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] in VALID_RELATED_MATERIAL_TYPES
        _validate_cbom_structural_conformance(cbom_types)

    def test_parameter_set_identifier_resolution_exhaustive(self):
        """
        Verifies:
        - Parameter sets are preserved for PQC algorithms (e.g. ML-KEM-768, ML-DSA-65).
        - Raw byte sizes (e.g. 1184 for ML-KEM-768) are NOT used as parameterSetIdentifier.
        - Unparameterized algorithms (e.g. 'ML-KEM') without variant omit parameterSetIdentifier.
        - Misleading size values (e.g. key_size=999 for AES) do NOT produce invalid parameterSetIdentifier.
        - Hash digest lengths (SHA-256 -> '256', MD5 -> '128') are correctly mapped.
        """
        findings = [
            {"id": "p1", "algorithm": "ML-KEM-768", "key_size": 1184, "asset_type": "algorithm"},
            {"id": "p2", "algorithm": "ML-KEM-512", "key_size": 800, "asset_type": "algorithm"},
            {"id": "p3", "algorithm": "ML-KEM-1024", "key_size": 1568, "asset_type": "algorithm"},
            {"id": "p4", "algorithm": "ML-KEM", "key_size": 1184, "asset_type": "algorithm"},
            {"id": "p5", "algorithm": "Kyber-768", "key_size": 768, "asset_type": "algorithm"},
            {"id": "p6", "algorithm": "ML-DSA-65", "key_size": 1952, "asset_type": "algorithm"},
            {"id": "p7", "algorithm": "AES-256", "key_size": 256, "asset_type": "algorithm"},
            {"id": "p8", "algorithm": "AES", "key_size": 999, "asset_type": "algorithm"},
            {"id": "p9", "algorithm": "SHA-256", "key_size": 256, "asset_type": "algorithm"},
            {"id": "p10", "algorithm": "SHA-512", "key_size": 512, "asset_type": "algorithm"},
            {"id": "p11", "algorithm": "MD5", "key_size": 128, "asset_type": "algorithm"},
            {"id": "p12", "algorithm": "RSA", "key_size": 2048, "asset_type": "algorithm"},
            {"id": "p13", "algorithm": "RSA", "key_size": 500, "asset_type": "algorithm"},
            {"id": "p14", "algorithm": "UnknownAlg", "key_size": 256, "asset_type": "algorithm"},
        ]
        cbom = generate_cyclonedx_cbom("Params Project", "scan-p", findings, 85)
        props_by_id = {c["bom-ref"]: c["cryptoProperties"]["algorithmProperties"] for c in cbom["components"]}

        assert props_by_id["crypto-asset-p1"]["parameterSetIdentifier"] == "ML-KEM-768"
        assert props_by_id["crypto-asset-p2"]["parameterSetIdentifier"] == "ML-KEM-512"
        assert props_by_id["crypto-asset-p3"]["parameterSetIdentifier"] == "ML-KEM-1024"
        assert "parameterSetIdentifier" not in props_by_id["crypto-asset-p4"]
        assert props_by_id["crypto-asset-p5"]["parameterSetIdentifier"] == "Kyber-768"
        assert props_by_id["crypto-asset-p6"]["parameterSetIdentifier"] == "ML-DSA-65"

        assert props_by_id["crypto-asset-p7"]["parameterSetIdentifier"] == "256"
        assert "parameterSetIdentifier" not in props_by_id["crypto-asset-p8"]
        assert props_by_id["crypto-asset-p9"]["parameterSetIdentifier"] == "256"
        assert props_by_id["crypto-asset-p10"]["parameterSetIdentifier"] == "512"
        assert props_by_id["crypto-asset-p11"]["parameterSetIdentifier"] == "128"
        assert props_by_id["crypto-asset-p12"]["parameterSetIdentifier"] == "2048"
        assert "parameterSetIdentifier" not in props_by_id["crypto-asset-p13"]
        assert "parameterSetIdentifier" not in props_by_id["crypto-asset-p14"]

        _validate_cbom_structural_conformance(cbom)

    def test_primitive_classification_substring_regressions_and_rsa_usage(self):
        """
        Regression tests for primitive classification:
        - Broad substring checks (e.g. 'dh', 'ec', 'sha') must NOT misclassify English words.
        - Context-aware RSA: signature for signing usage, pke for encryption/keygen.
        - AEAD modes take precedence over generic block/stream ciphers.
        """
        assert _map_algorithm_primitive("width", "general") == "other"
        assert _map_algorithm_primitive("shadow", "general") == "other"
        assert _map_algorithm_primitive("adhoc", "general") == "other"
        assert _map_algorithm_primitive("secretkey", "general") == "other"
        assert _map_algorithm_primitive("directcipher", "general") == "other"

        assert _map_algorithm_primitive("RSA", "token_signing") == "signature"
        assert _map_algorithm_primitive("RSA", "sign") == "signature"
        assert _map_algorithm_primitive("RSA", "verify") == "signature"
        assert _map_algorithm_primitive("RSA", "key_generation") == "pke"
        assert _map_algorithm_primitive("RSA", "encryption") == "pke"
        assert _map_algorithm_primitive("RSA", "decrypt") == "pke"

        assert _map_algorithm_primitive("AES-GCM", "encryption") == "ae"
        assert _map_algorithm_primitive("AES-CCM", "encryption") == "ae"
        assert _map_algorithm_primitive("ChaCha20-Poly1305", "encryption") == "ae"

    def test_security_strength_calculations_exhaustive_and_boundaries(self):
        """
        Validates NIST SP 800-57 classical security levels and NIST PQC categories 1-5:
        - ML-KEM, ML-DSA, Falcon, SLH-DSA
        - RSA standard and sub-standard sizes (<1024 bits -> None)
        - ECC curves
        - Broken algorithms (MD5, SHA-1) -> (None, None)
        """
        assert _calculate_security_strengths("ML-KEM-512", None, False) == (128, 1)
        assert _calculate_security_strengths("ML-KEM-768", None, False) == (192, 3)
        assert _calculate_security_strengths("ML-KEM-1024", None, False) == (256, 5)
        assert _calculate_security_strengths("ML-DSA-44", None, False) == (128, 2)
        assert _calculate_security_strengths("ML-DSA-65", None, False) == (192, 3)
        assert _calculate_security_strengths("ML-DSA-87", None, False) == (256, 5)
        assert _calculate_security_strengths("Falcon-512", None, False) == (128, 1)
        assert _calculate_security_strengths("Falcon-1024", None, False) == (256, 5)
        assert _calculate_security_strengths("SLH-DSA-128", None, False) == (128, 1)
        assert _calculate_security_strengths("SLH-DSA-192", None, False) == (192, 3)
        assert _calculate_security_strengths("SLH-DSA-256", None, False) == (256, 5)

        assert _calculate_security_strengths("RSA", 2048, True) == (112, 0)
        assert _calculate_security_strengths("RSA", 3072, True) == (128, 0)
        assert _calculate_security_strengths("RSA", 4096, True) == (128, 0)
        assert _calculate_security_strengths("RSA", 7680, True) == (192, 0)
        assert _calculate_security_strengths("RSA", 15360, True) == (256, 0)
        assert _calculate_security_strengths("RSA", 1024, True) == (80, 0)
        assert _calculate_security_strengths("RSA", 512, True) == (None, 0)

        assert _calculate_security_strengths("SECP256R1", 256, True) == (128, 0)
        assert _calculate_security_strengths("SECP384R1", 384, True) == (192, 0)
        assert _calculate_security_strengths("SECP521R1", 521, True) == (256, 0)

        assert _calculate_security_strengths("SHA-256", 256, False) == (128, 0)
        assert _calculate_security_strengths("SHA-384", 384, False) == (192, 0)
        assert _calculate_security_strengths("SHA-512", 512, False) == (256, 0)
        assert _calculate_security_strengths("MD5", 128, True) == (None, None)
        assert _calculate_security_strengths("SHA-1", 160, True) == (None, None)

    def test_quantum_status_consistency_and_normalization(self):
        """
        Verifies quantum-status consistency:
        - 'quantum_safe' -> keynova:quantum_status == 'quantum_safe', keynova:quantum_vulnerable == 'false'
        - 'quantum_vulnerable' -> keynova:quantum_status == 'quantum_vulnerable', keynova:quantum_vulnerable == 'true', level == 0
        - 'classical_weakness' -> keynova:quantum_status == 'classical_weakness', keynova:quantum_vulnerable == 'false'
        - 'unknown' -> keynova:quantum_status == 'unknown', keynova:quantum_vulnerable == 'unknown'
        - Missing status with unknown algorithm must NOT be stamped as definitively quantum-vulnerable
        """
        findings = [
            {"id": "q1", "algorithm": "ML-KEM-768", "quantum_status": "quantum_safe"},
            {"id": "q2", "algorithm": "RSA-2048", "quantum_status": "quantum_vulnerable", "key_size": 2048},
            {"id": "q3", "algorithm": "MD5", "quantum_status": "classical_weakness"},
            {"id": "q4", "algorithm": "UnknownCipher", "quantum_status": "unknown"},
            {"id": "q5", "algorithm": "GenericCustomScheme"},
            {"id": "q6", "algorithm": "ML-KEM-1024"},
            {"id": "q7", "algorithm": "RSA-3072", "key_size": 3072},
        ]
        cbom = generate_cyclonedx_cbom("Quantum Consistency", "scan-q", findings, 77)
        comps = {c["bom-ref"]: c for c in cbom["components"]}

        def get_props(comp):
            return {p["name"]: p["value"] for p in comp["properties"]}

        # 1. Known quantum-safe
        p1 = get_props(comps["crypto-asset-q1"])
        assert p1["keynova:quantum_status"] == "quantum_safe"
        assert p1["keynova:quantum_vulnerable"] == "false"
        assert comps["crypto-asset-q1"]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3

        # 2. Known quantum-vulnerable
        p2 = get_props(comps["crypto-asset-q2"])
        assert p2["keynova:quantum_status"] == "quantum_vulnerable"
        assert p2["keynova:quantum_vulnerable"] == "true"
        assert comps["crypto-asset-q2"]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0

        # 3. Classical weakness
        p3 = get_props(comps["crypto-asset-q3"])
        assert p3["keynova:quantum_status"] == "classical_weakness"
        assert p3["keynova:quantum_vulnerable"] == "false"
        assert "nistQuantumSecurityLevel" not in comps["crypto-asset-q3"]["cryptoProperties"]["algorithmProperties"]

        # 4. Explicit unknown status
        p4 = get_props(comps["crypto-asset-q4"])
        assert p4["keynova:quantum_status"] == "unknown"
        assert p4["keynova:quantum_vulnerable"] == "unknown"
        assert "nistQuantumSecurityLevel" not in comps["crypto-asset-q4"]["cryptoProperties"]["algorithmProperties"]

        # 5. Missing status on unrecognized algorithm must NOT be marked quantum-vulnerable
        p5 = get_props(comps["crypto-asset-q5"])
        assert p5["keynova:quantum_status"] == "unknown"
        assert p5["keynova:quantum_vulnerable"] == "unknown"
        assert "nistQuantumSecurityLevel" not in comps["crypto-asset-q5"]["cryptoProperties"]["algorithmProperties"]

        # 6. Missing status on known PQC inferred as safe
        p6 = get_props(comps["crypto-asset-q6"])
        assert p6["keynova:quantum_status"] == "quantum_safe"
        assert p6["keynova:quantum_vulnerable"] == "false"

        # 7. Missing status on known RSA inferred as vulnerable
        p7 = get_props(comps["crypto-asset-q7"])
        assert p7["keynova:quantum_status"] == "quantum_vulnerable"
        assert p7["keynova:quantum_vulnerable"] == "true"

        _validate_cbom_structural_conformance(cbom)


# ============================================================================
# 3. EDGE CASES, ROBUSTNESS & JSON SERIALIZATION TESTS
# ============================================================================

class TestCycloneDxEdgeCasesAndSerialization:
    """Verifies empty findings, missing optional fields, and JSON serialization."""

    def test_empty_findings_produces_valid_empty_components_list(self):
        """An empty findings list must produce a valid CBOM with components: []."""
        cbom = generate_cyclonedx_cbom("Clean Project", "scan-empty", [], 100)
        assert cbom["components"] == []
        assert cbom["metadata"]["properties"][0]["value"] == "100"
        serialized = json.dumps(cbom)
        loaded = json.loads(serialized)
        assert loaded["components"] == []
        _validate_cbom_structural_conformance(cbom)

    def test_missing_optional_fields_and_sensible_defaults(self):
        """Missing keys in finding dicts must not trigger KeyErrors or invent invalid values."""
        sparse_findings = [
            {},
            {"algorithm": None, "usage": None, "key_size": "invalid_int"},
        ]
        cbom = generate_cyclonedx_cbom(None, None, sparse_findings, 50)
        assert len(cbom["components"]) == 2
        for c in cbom["components"]:
            assert c["type"] == "cryptographic-asset"
            cp = c["cryptoProperties"]
            assert cp["assetType"] in VALID_CYCLONEDX_ASSET_TYPES
            assert set(cp.keys()).issubset(ALLOWED_CRYPTO_PROPERTIES)
            if "algorithmProperties" in cp:
                alg_props = cp["algorithmProperties"]
                assert set(alg_props.keys()).issubset(ALLOWED_ALGORITHM_PROPERTIES)
                assert "classicalSecurityLevel" not in alg_props
        _validate_cbom_structural_conformance(cbom)

    def test_json_serializability_no_cycles(self):
        """Ensures the entire generated dictionary can be serialized without type errors."""
        sample_findings = [
            {
                "id": f"find-{i}",
                "algorithm": f"Alg-{i}",
                "key_size": 256,
                "severity": "medium",
                "hndl": False,
                "file_path": f"src/mod_{i}.py",
                "line_start": i * 10,
                "line_end": i * 10 + 5,
            }
            for i in range(10)
        ]
        cbom = generate_cyclonedx_cbom("Payment Engine", "scan-12345678", sample_findings, 75)
        serialized = json.dumps(cbom, indent=2)
        assert len(serialized) > 0
        loaded = json.loads(serialized)
        assert len(loaded["components"]) == 10
        assert loaded["metadata"]["component"]["name"] == "Payment Engine"
        _validate_cbom_structural_conformance(cbom)


# ============================================================================
# 4. FIXTURE INTEGRATION TESTS (vulnerable vs remediated payment suites)
# ============================================================================

class TestCycloneDxFixtureIntegration:
    """Verifies CBOM generation using actual scanned data from test fixtures."""

    def test_vulnerable_fixture_cbom_export(self):
        """
        Scans vulnerable_payment_suite and verifies exported CBOM:
        1. 4 cryptographic-asset components created.
        2. Unique bom-refs.
        3. Strict schema-compliance for cryptoProperties and algorithmProperties.
        4. Correct primitive mapping (MD5 -> hash, SECP256R1 -> signature, RSA -> pke).
        5. Defensible security strength values (RSA-2048 -> 112 bits, ECC-256 -> 128 bits).
        6. Keynova-specific properties and source occurrences preserved.
        7. Full CycloneDX 1.6 structural conformance.
        """
        findings = _scan_fixture_directory(VULN_FIXTURE_DIR)
        assert len(findings) == 4

        cbom = generate_cyclonedx_cbom(
            project_name="Vulnerable Payment Suite",
            scan_id="scan-vuln-001",
            findings=findings,
            readiness_score=48,
        )

        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert len(cbom["components"]) == 4

        # Validate schema field compliance on every component
        for c in cbom["components"]:
            assert c["type"] == "cryptographic-asset"
            cp = c["cryptoProperties"]
            assert cp["assetType"] in VALID_CYCLONEDX_ASSET_TYPES
            unsupported = set(cp.keys()) - ALLOWED_CRYPTO_PROPERTIES
            assert not unsupported, f"Unsupported fields in cryptoProperties: {unsupported}"

            if "algorithmProperties" in cp:
                ap = cp["algorithmProperties"]
                unsupported_ap = set(ap.keys()) - ALLOWED_ALGORITHM_PROPERTIES
                assert not unsupported_ap, f"Unsupported fields in algorithmProperties: {unsupported_ap}"
                assert ap["primitive"] in VALID_CYCLONEDX_PRIMITIVES

        # 1. RSA component
        rsa_comp = next(c for c in cbom["components"] if "RSA" in c["name"] and "/" not in c["name"])
        rsa_cp = rsa_comp["cryptoProperties"]
        rsa_ap = rsa_cp["algorithmProperties"]
        assert rsa_ap["primitive"] == "pke"
        assert rsa_ap["classicalSecurityLevel"] == 112
        assert rsa_ap["parameterSetIdentifier"] == "2048"
        assert rsa_ap["nistQuantumSecurityLevel"] == 0

        rsa_props = {p["name"]: p["value"] for p in rsa_comp["properties"]}
        assert rsa_props["keynova:hndl"] == "true"
        assert rsa_props["keynova:quantum_vulnerable"] == "true"
        assert rsa_props["keynova:key_size"] == "2048"
        assert rsa_comp["evidence"]["occurrences"][0]["location"].replace("\\", "/") == "backend/crypto_service.py"

        # 2. ECC component
        ecc_comp = next(c for c in cbom["components"] if "ECC" in c["name"])
        ecc_ap = ecc_comp["cryptoProperties"]["algorithmProperties"]
        assert ecc_ap["primitive"] == "signature"
        assert ecc_ap["classicalSecurityLevel"] == 128
        assert ecc_ap["parameterSetIdentifier"] == "256"
        assert ecc_ap["curve"] == "secp256r1"
        assert ecc_ap["nistQuantumSecurityLevel"] == 0

        # 3. MD5 component
        md5_comp = next(c for c in cbom["components"] if "MD5" in c["name"])
        md5_ap = md5_comp["cryptoProperties"]["algorithmProperties"]
        assert md5_ap["primitive"] == "hash"
        assert md5_ap["parameterSetIdentifier"] == "128"
        assert "classicalSecurityLevel" not in md5_ap
        assert "nistQuantumSecurityLevel" not in md5_ap

        # 4. Manifest component (PyCryptodome)
        dep_comp = next(c for c in cbom["components"] if "DES" in c["name"])
        assert dep_comp["cryptoProperties"]["assetType"] == "algorithm"
        dep_ap = dep_comp["cryptoProperties"]["algorithmProperties"]
        assert dep_ap["primitive"] in VALID_CYCLONEDX_PRIMITIVES

        _validate_cbom_structural_conformance(cbom)

    def test_remediated_fixture_cbom_export(self):
        """
        Scans remediated_payment_suite and verifies exported CBOM:
        1. 0 vulnerable components.
        2. Components list is empty ([]).
        3. Readiness score 100 in metadata.
        4. Full CycloneDX 1.6 structural conformance.
        """
        findings = _scan_fixture_directory(REMED_FIXTURE_DIR)
        assert len(findings) == 0

        cbom = generate_cyclonedx_cbom(
            project_name="Remediated Payment Suite",
            scan_id="scan-remed-001",
            findings=findings,
            readiness_score=100,
        )

        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert cbom["components"] == []

        props = {p["name"]: p["value"] for p in cbom["metadata"]["properties"]}
        assert props.get("keynova:readiness_score") == "100"

        _validate_cbom_structural_conformance(cbom)


# ============================================================================
# 5. COMPREHENSIVE MULTI-ASSET CBOM STRUCTURAL CONFORMANCE
# ============================================================================

class TestCycloneDxMultiAssetStructuralValidation:
    """
    Validates complete CycloneDX 1.6 documents across all cryptographic asset types:
    algorithms, certificates, protocols, and related cryptographic materials.
    """

    def test_validate_rich_multi_asset_bom(self):
        """
        Constructs a diverse finding suite representing:
        - RSA public key encryption (algorithm)
        - ECC signature (algorithm)
        - ML-KEM-768 post-quantum key encapsulation (algorithm)
        - SHA-256 cryptographic hash (algorithm)
        - X.509 Certificate (certificate)
        - TLS 1.3 Protocol (protocol)
        - 256-bit AES secret key (related-crypto-material)

        Verifies full structural conformance against the official CycloneDX 1.6 schema.
        """
        rich_findings = [
            {
                "id": "asset-rsa-001",
                "asset_type": "source_code",
                "algorithm": "RSA",
                "key_size": 2048,
                "usage": "key_generation",
                "quantum_status": "quantum_vulnerable",
                "hndl": True,
                "file_path": "src/crypto/rsa_signer.py",
                "line_start": 42,
                "line_end": 48,
                "code_snippet": "rsa.generate_private_key(public_exponent=65537, key_size=2048)",
                "evidence": "Legacy 2048-bit RSA key establishment."
            },
            {
                "id": "asset-ecc-002",
                "asset_type": "source_code",
                "algorithm": "ECC-SECP256R1",
                "key_size": 256,
                "usage": "token_signing",
                "quantum_status": "quantum_vulnerable",
                "hndl": True,
                "file_path": "src/auth/jwt.py",
                "line_start": 15,
                "line_end": 18,
                "code_snippet": "ec.generate_private_key(ec.SECP256R1())",
                "evidence": "ECDSA signing using NIST P-256."
            },
            {
                "id": "asset-kem-003",
                "asset_type": "source_code",
                "algorithm": "ML-KEM-768",
                "key_size": 768,
                "usage": "kem",
                "quantum_status": "quantum_safe",
                "hndl": False,
                "file_path": "src/pq/kem.py",
                "line_start": 100,
                "line_end": 105,
                "code_snippet": "kyber.encapsulate()",
                "evidence": "FIPS 203 ML-KEM-768 Key Encapsulation Mechanism."
            },
            {
                "id": "asset-hash-004",
                "asset_type": "source_code",
                "algorithm": "SHA-256",
                "key_size": 256,
                "usage": "hashing",
                "quantum_status": "quantum_safe",
                "hndl": False,
                "file_path": "src/hasher.py",
                "line_start": 30,
                "line_end": 32,
                "code_snippet": "hashlib.sha256(data)",
                "evidence": "Secure cryptographic hash function."
            },
            {
                "id": "asset-cert-005",
                "asset_type": "certificate",
                "algorithm": "X.509",
                "subject_name": "CN=gateway.payment.internal",
                "issuer_name": "CN=Internal Enterprise CA",
                "quantum_status": "quantum_vulnerable",
                "hndl": False,
                "file_path": "certs/server.crt",
                "line_start": 1,
                "line_end": 1,
                "evidence": "X.509 TLS Server Certificate."
            },
            {
                "id": "asset-prot-006",
                "asset_type": "protocol",
                "algorithm": "TLSv1.3",
                "quantum_status": "quantum_safe",
                "hndl": False,
                "file_path": "nginx/nginx.conf",
                "line_start": 80,
                "line_end": 85,
                "evidence": "Transport Layer Security 1.3 Endpoint."
            },
            {
                "id": "asset-mat-007",
                "asset_type": "key",
                "algorithm": "AES-256-Key",
                "key_size": 256,
                "quantum_status": "quantum_safe",
                "hndl": False,
                "file_path": "secrets/aes.key",
                "line_start": 1,
                "line_end": 1,
                "evidence": "256-bit symmetric encryption key."
            },
        ]

        cbom = generate_cyclonedx_cbom(
            project_name="Multi-Asset Cloud Platform",
            scan_id="scan-multi-asset-999",
            findings=rich_findings,
            readiness_score=88,
        )

        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert len(cbom["components"]) == 7

        comps_by_id = {c["bom-ref"]: c for c in cbom["components"]}

        # 1. RSA checks
        c_rsa = comps_by_id["crypto-asset-asset-rsa-001"]
        assert c_rsa["cryptoProperties"]["assetType"] == "algorithm"
        assert c_rsa["cryptoProperties"]["algorithmProperties"]["primitive"] == "pke"
        assert c_rsa["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 112
        assert c_rsa["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0

        # 2. ECC checks
        c_ecc = comps_by_id["crypto-asset-asset-ecc-002"]
        assert c_ecc["cryptoProperties"]["assetType"] == "algorithm"
        assert c_ecc["cryptoProperties"]["algorithmProperties"]["primitive"] == "signature"
        assert c_ecc["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 128
        assert c_ecc["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0

        # 3. ML-KEM checks
        c_kem = comps_by_id["crypto-asset-asset-kem-003"]
        assert c_kem["cryptoProperties"]["assetType"] == "algorithm"
        assert c_kem["cryptoProperties"]["algorithmProperties"]["primitive"] == "kem"
        assert c_kem["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 192
        assert c_kem["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3

        # 4. SHA-256 checks
        c_hash = comps_by_id["crypto-asset-asset-hash-004"]
        assert c_hash["cryptoProperties"]["assetType"] == "algorithm"
        assert c_hash["cryptoProperties"]["algorithmProperties"]["primitive"] == "hash"
        assert c_hash["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 128
        assert c_hash["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0

        # 5. Certificate checks
        c_cert = comps_by_id["crypto-asset-asset-cert-005"]
        assert c_cert["cryptoProperties"]["assetType"] == "certificate"
        assert "certificateProperties" in c_cert["cryptoProperties"]
        assert c_cert["cryptoProperties"]["certificateProperties"]["subjectName"] == "CN=gateway.payment.internal"

        # 6. Protocol checks
        c_prot = comps_by_id["crypto-asset-asset-prot-006"]
        assert c_prot["cryptoProperties"]["assetType"] == "protocol"
        assert "protocolProperties" in c_prot["cryptoProperties"]
        assert c_prot["cryptoProperties"]["protocolProperties"]["type"] == "tls"

        # 7. Material checks
        c_mat = comps_by_id["crypto-asset-asset-mat-007"]
        assert c_mat["cryptoProperties"]["assetType"] == "related-crypto-material"
        assert "relatedCryptoMaterialProperties" in c_mat["cryptoProperties"]
        assert c_mat["cryptoProperties"]["relatedCryptoMaterialProperties"]["size"] == 256

        # Full structural schema conformance
        _validate_cbom_structural_conformance(cbom)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

