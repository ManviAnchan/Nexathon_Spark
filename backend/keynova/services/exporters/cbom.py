import json
import re
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

VALID_CYCLONEDX_ASSET_TYPES = {
    "algorithm",
    "certificate",
    "protocol",
    "related-crypto-material",
}

VALID_CYCLONEDX_PRIMITIVES = {
    "drbg",
    "mac",
    "block-cipher",
    "stream-cipher",
    "signature",
    "hash",
    "pke",
    "xof",
    "kdf",
    "key-agree",
    "kem",
    "ae",
    "combiner",
    "other",
    "unknown",
}


def _map_asset_type(raw_type: Any) -> str:
    """
    Maps Keynova internal asset types to official CycloneDX 1.6 CBOM assetType enum:
    'algorithm' | 'certificate' | 'protocol' | 'related-crypto-material'
    """
    if not raw_type:
        return "algorithm"

    normalized = str(raw_type).strip().lower()
    if normalized in VALID_CYCLONEDX_ASSET_TYPES:
        return normalized

    if "cert" in normalized or "x509" in normalized:
        return "certificate"
    if "tls" in normalized or "protocol" in normalized or "endpoint" in normalized:
        return "protocol"
    if "key" in normalized or "secret" in normalized or "material" in normalized:
        return "related-crypto-material"

    # In Keynova, 'source_code', 'manifest', and code-level cryptographic findings
    # describe cryptographic algorithms and primitives.
    return "algorithm"


def _resolve_parameter_set_identifier(
    algorithm: Optional[str],
    key_size: Any,
    finding: Dict[str, Any]
) -> Optional[str]:
    """
    Resolves the standardized parameterSetIdentifier for algorithmProperties.
    CycloneDX 1.6 defines parameterSetIdentifier as:
    'An identifier for the parameter set of the cryptographic algorithm.
     Examples: in AES128, "128" identifies the key length in bits;
     in SHA256, "256" identifies the digest length;
     "SHA2-128s" identifies a parameter set used in SLH-DSA (FIPS205).'

    Rules:
    - Never blindly equate raw key_size with parameterSetIdentifier for every algorithm.
    - For PQC algorithms (ML-KEM, ML-DSA, Falcon, SLH-DSA), preserve the standardized
      parameter set name (e.g. 'ML-KEM-768', 'ML-DSA-65', 'Falcon-512').
    - Do not infer a PQC parameter set from key byte lengths (e.g. 1184) unless the
      algorithm name already confirms the variant.
    - For conventional symmetric ciphers (AES), use standardized bit length ('128', '192', '256').
    - For hashes (SHA-2/3), use standardized digest length ('256', '384', '512').
    - For RSA, use the standardized modulus bit length if valid ('2048', '3072', '4096').
    - For curves, if not in 'curve' property, or omit if curve is populated.
    - If unknown or unidentifiable, return None (omit the field).
    """
    if not algorithm:
        return None

    alg_clean = str(algorithm).strip().upper()
    if alg_clean in ["UNKNOWN", "NONE", "N/A", ""]:
        return None

    # 1. Explicit parameter set from finding
    explicit_param = finding.get("parameter_set") or finding.get("parameter_set_identifier")
    if explicit_param:
        return str(explicit_param).strip()

    # 2. Post-Quantum Cryptography: Standardized parameter set names
    if "ML-KEM" in alg_clean:
        if "1024" in alg_clean:
            return "ML-KEM-1024"
        if "768" in alg_clean:
            return "ML-KEM-768"
        if "512" in alg_clean:
            return "ML-KEM-512"
        return None

    if "KYBER" in alg_clean:
        if "1024" in alg_clean:
            return "Kyber-1024"
        if "768" in alg_clean:
            return "Kyber-768"
        if "512" in alg_clean:
            return "Kyber-512"
        return None

    if "ML-DSA" in alg_clean:
        if "87" in alg_clean:
            return "ML-DSA-87"
        if "65" in alg_clean:
            return "ML-DSA-65"
        if "44" in alg_clean:
            return "ML-DSA-44"
        return None

    if "DILITHIUM" in alg_clean:
        if "5" in alg_clean:
            return "Dilithium5"
        if "3" in alg_clean:
            return "Dilithium3"
        if "2" in alg_clean:
            return "Dilithium2"
        return None

    if "FALCON" in alg_clean:
        if "1024" in alg_clean:
            return "Falcon-1024"
        if "512" in alg_clean:
            return "Falcon-512"
        return None

    if "SLH-DSA" in alg_clean or "SPHINCS" in alg_clean:
        for suffix in ["256S", "256F", "192S", "192F", "128S", "128F"]:
            if suffix in alg_clean:
                return f"SLH-DSA-{suffix}"
        if "256" in alg_clean:
            return "SLH-DSA-256"
        if "192" in alg_clean:
            return "SLH-DSA-192"
        if "128" in alg_clean:
            return "SLH-DSA-128"
        return None

    # 3. Conventional algorithms: key length or digest length in bits
    k_int: Optional[int] = None
    if key_size is not None:
        try:
            k_int = int(key_size)
            if k_int <= 0:
                k_int = None
        except (ValueError, TypeError):
            k_int = None

    # AES: bit length 128, 192, 256
    if alg_clean.startswith("AES") or "AES-" in alg_clean:
        if "256" in alg_clean or k_int == 256:
            return "256"
        if "192" in alg_clean or k_int == 192:
            return "192"
        if "128" in alg_clean or k_int == 128:
            return "128"
        return None

    # Hashes: SHA-2 / SHA-3 / MD5 / SHA-1
    if any(h in alg_clean for h in ["SHA-256", "SHA256", "SHA3-256"]):
        return "256"
    if any(h in alg_clean for h in ["SHA-384", "SHA384", "SHA3-384"]):
        return "384"
    if any(h in alg_clean for h in ["SHA-512", "SHA512", "SHA3-512"]):
        return "512"
    if any(h in alg_clean for h in ["SHA-224", "SHA224", "SHA3-224"]):
        return "224"
    if "MD5" in alg_clean:
        if k_int in [None, 128]:
            return "128"
        return None
    if "SHA-1" in alg_clean or "SHA1" in alg_clean:
        if k_int in [None, 160]:
            return "160"
        return None

    # RSA: modulus bit length (must be standard RSA size)
    if alg_clean == "RSA" or alg_clean.startswith("RSA-") or alg_clean.startswith("RSA_"):
        effective_key = k_int
        if effective_key is None:
            for sz in [15360, 7680, 4096, 3072, 2048, 1024]:
                if str(sz) in alg_clean:
                    effective_key = sz
                    break
        if effective_key in [1024, 2048, 3072, 4096, 7680, 15360]:
            return str(effective_key)
        return None

    # Elliptic curves: field size in bits (256, 384, 521)
    if any(ec in alg_clean for ec in ["ECC", "ECDSA", "ECDH", "SECP", "ED25519", "X25519", "P-256", "P-384", "P-521"]):
        if "521" in alg_clean or k_int == 521:
            return "521"
        if "384" in alg_clean or k_int == 384:
            return "384"
        if "256" in alg_clean or "25519" in alg_clean or k_int == 256:
            return "256"
        if k_int in [256, 384, 521]:
            return str(k_int)
        return None

    return None


def _map_algorithm_primitive(algorithm: Optional[str], usage: Optional[str]) -> str:
    """
    Maps algorithm and usage to CycloneDX 1.6 primitive categories:
    'pke' | 'signature' | 'kem' | 'hash' | 'block-cipher' | 'stream-cipher' |
    'key-agree' | 'ae' | 'mac' | 'kdf' | 'drbg' | 'combiner' | 'other' | 'unknown'
    """
    alg_clean = (algorithm or "").strip()
    alg_lower = alg_clean.lower()
    usage_lower = (usage or "").strip().lower()

    if not alg_lower and not usage_lower:
        return "unknown"

    if alg_lower in ["unknown", "none", "n/a", "null"]:
        return "unknown"

    # Multi-algorithm dependency declarations (e.g. "DES/RSA/RC4")
    if "/" in alg_lower and (usage_lower in ["dependency", "manifest"] or "dep" in usage_lower):
        return "combiner"

    # Authenticated Encryption (AEAD) - must be checked before stream/block ciphers
    # Word-bounded check prevents false positives on words like 'passive'
    aead_alg_match = any(
        re.search(rf"(?:^|[-_./\s]){ae}(?:$|[-_./\s0-9])", alg_lower)
        for ae in ["gcm", "ccm", "poly1305", "eax", "ocb", "siv"]
    ) or "chacha20-poly1305" in alg_lower
    aead_usage_match = any(
        ae in usage_lower
        for ae in ["gcm", "ccm", "poly1305", "eax", "ocb", "siv", "ae", "aead", "authenticated_encryption", "authenticated"]
    )
    if aead_alg_match or aead_usage_match:
        return "ae"

    # Key Encapsulation Mechanism (KEM)
    if "kem" in alg_lower or "kem" in usage_lower or re.search(r"\b(kyber|frodo|hqc|bike)\b", alg_lower):
        return "kem"

    # Message Authentication Codes (MAC / HMAC) - checked before hash
    if re.search(r"\b(mac|hmac|cmac|gmac|kmac)\b", alg_lower) or "hmac" in alg_lower or "cmac" in alg_lower or \
       re.search(r"\bmac\b", usage_lower) or "hmac" in usage_lower:
        return "mac"

    # Cryptographic Hash Functions (CycloneDX 1.6 uses 'hash', not 'digest')
    # Bounded match prevents false positives on English words like 'shadow' or 'width'
    hash_alg_match = (
        re.search(r"\b(md5|sha1|sha2|sha3|digest|blake2b|blake2s|blake3|ripemd|sm3)\b", alg_lower) or
        any(h in alg_lower for h in ["sha-", "sha_", "sha256", "sha384", "sha512", "sha224", "sha3-", "blake2", "blake3"])
    )
    if hash_alg_match or "hash" in usage_lower:
        return "hash"

    # Digital Signatures
    # Context-aware: RSA with signing usage is a signature!
    is_signing_usage = any(u in usage_lower for u in ["sign", "signature", "token_signing", "verify"])
    sig_alg_match = (
        re.search(r"\b(dsa|ecdsa|ed25519|ed448|falcon|sphincs|slh-dsa|ml-dsa|dilithium)\b", alg_lower) or
        any(s in alg_lower for s in ["ecdsa", "ed25519", "ed448", "falcon", "sphincs", "slh-dsa", "ml-dsa", "dilithium"])
    )
    if is_signing_usage or sig_alg_match:
        return "signature"

    # Key Agreement
    # Bounded 'dh' avoids false positives on words like 'width', 'shadow', 'adhoc'
    dh_match = (
        re.search(r"\b(ecdh|diffie-hellman|dh|ffdh|x25519|x448)\b", alg_lower) or
        alg_lower.startswith("dh-") or alg_lower.startswith("dh_") or "-dh" in alg_lower or "_dh" in alg_lower
    )
    # Bounded 'ec' avoids false positives on words like 'directcipher' or 'secretkey'
    ec_key_exchange = (
        (re.search(r"\b(ec|ecc)\b", alg_lower) or "secp" in alg_lower) and
        any(u in usage_lower for u in ["key_agree", "key-agree", "key_exchange", "exchange"])
    )
    if dh_match or ec_key_exchange or any(ka in usage_lower for ka in ["key_agree", "key-agree", "key_exchange"]):
        return "key-agree"

    # Stream Ciphers (e.g. RC4, ChaCha20, Salsa20)
    if re.search(r"\b(rc4|chacha20|salsa20)\b", alg_lower) or "stream" in usage_lower:
        return "stream-cipher"

    # Block Ciphers (specific cipher families only; do not match generic word 'cipher')
    block_ciphers = ["aes", "des", "3des", "blowfish", "camellia", "sm4", "twofish", "serpent", "idea", "cast5"]
    if any(re.search(rf"\b{bc}\b", alg_lower) or f"{bc}-" in alg_lower or f"{bc}_" in alg_lower for bc in block_ciphers) or \
       alg_lower in block_ciphers or "block" in usage_lower:
        return "block-cipher"

    # Public Key Encryption (PKE) - only asymmetric encryption or explicit PKE
    is_encrypt_usage = any(u in usage_lower for u in ["encrypt", "pke", "key_generation", "keygen", "decrypt"])
    pke_alg_match = re.search(r"\b(rsa|elgamal|paillier)\b", alg_lower)
    if "pke" in usage_lower or "pke" in alg_lower or (pke_alg_match and is_encrypt_usage):
        return "pke"

    # Key Derivation Functions
    if any(k in alg_lower or k in usage_lower for k in ["kdf", "pbkdf", "hkdf", "scrypt", "argon2", "bcrypt"]):
        return "kdf"

    # Deterministic Random Bit Generators / PRNGs
    if "drbg" in alg_lower or "drbg" in usage_lower or "prng" in alg_lower or "random" in usage_lower:
        return "drbg"

    # Generic or unknown algorithms with generic usage must not receive misleading classifications
    if alg_lower in ["unknown", "none"] or not alg_lower:
        return "unknown"

    return "other"


def _calculate_security_strengths(
    algorithm: Optional[str],
    key_size: Any,
    is_quantum_vulnerable: bool
) -> Tuple[Optional[int], Optional[int]]:
    """
    Computes defensible classicalSecurityLevel (in bits) and nistQuantumSecurityLevel (0..6)
    based on NIST SP 800-57 Part 1 Rev. 5 and NIST Post-Quantum Cryptography standards.

    Rules:
    - Never assign nistQuantumSecurityLevel = 3 to an arbitrary algorithm simply because
      it is marked quantum-safe.
    - Assign a NIST quantum security level only when the algorithm can be reliably identified
      and mapped to an appropriate documented category (1..5 for known PQC, 0 for broken/vulnerable).
    - Return None when the level cannot be established reliably.
    - Identify ML-KEM and ML-DSA variants using their algorithm names rather than inferring
      their parameter sets from public-key byte lengths.
    - Keep classical security strength separate from raw key size.
    - Do not invent security-strength values for broken, unknown, incomplete, or composite algorithms.
    """
    if not algorithm:
        return None, None

    alg_clean = str(algorithm).strip().upper()
    if not alg_clean or alg_clean in ["UNKNOWN", "NONE"]:
        return None, None

    # Multi-algorithm composite manifests (e.g., "DES/RSA/RC4", "MD5/SHA1/AES")
    if "/" in alg_clean:
        return None, None

    k_int: Optional[int] = None
    if key_size is not None:
        try:
            k_int = int(key_size)
            if k_int <= 0:
                k_int = None
        except (ValueError, TypeError):
            k_int = None

    classical_sec_level: Optional[int] = None
    nist_q_level: Optional[int] = None

    # 1. Post-Quantum Cryptography (PQC): Identify variants strictly from algorithm names
    if "ML-KEM" in alg_clean or "KYBER" in alg_clean:
        if "1024" in alg_clean:
            classical_sec_level = 256
            nist_q_level = 5
        elif "768" in alg_clean:
            classical_sec_level = 192
            nist_q_level = 3
        elif "512" in alg_clean:
            classical_sec_level = 128
            nist_q_level = 1
        else:
            # Incomplete or unparameterized algorithm name (e.g. just "ML-KEM" or "Kyber")
            # Do NOT infer from public-key byte length (e.g. 1184).
            classical_sec_level = None
            nist_q_level = None
        return classical_sec_level, nist_q_level

    if "ML-DSA" in alg_clean or "DILITHIUM" in alg_clean:
        if "87" in alg_clean or "DILITHIUM5" in alg_clean or "DILITHIUM-5" in alg_clean:
            classical_sec_level = 256
            nist_q_level = 5
        elif "65" in alg_clean or "DILITHIUM3" in alg_clean or "DILITHIUM-3" in alg_clean:
            classical_sec_level = 192
            nist_q_level = 3
        elif "44" in alg_clean or "DILITHIUM2" in alg_clean or "DILITHIUM-2" in alg_clean:
            classical_sec_level = 128
            nist_q_level = 2
        else:
            classical_sec_level = None
            nist_q_level = None
        return classical_sec_level, nist_q_level

    if "FALCON" in alg_clean:
        if "1024" in alg_clean:
            classical_sec_level = 256
            nist_q_level = 5
        elif "512" in alg_clean:
            classical_sec_level = 128
            nist_q_level = 1
        else:
            classical_sec_level = None
            nist_q_level = None
        return classical_sec_level, nist_q_level

    if "SLH-DSA" in alg_clean or "SPHINCS" in alg_clean:
        if "256" in alg_clean:
            classical_sec_level = 256
            nist_q_level = 5
        elif "192" in alg_clean:
            classical_sec_level = 192
            nist_q_level = 3
        elif "128" in alg_clean:
            classical_sec_level = 128
            nist_q_level = 1
        else:
            classical_sec_level = None
            nist_q_level = None
        return classical_sec_level, nist_q_level

    # 2. Classical, Symmetric, and Standard Hash Algorithms (NIST Quantum Level = 0)
    # 2a. RSA (NIST SP 800-57 Part 1 Rev. 5, Table 2)
    if alg_clean == "RSA" or alg_clean.startswith("RSA-") or alg_clean.startswith("RSA_"):
        # Resolve effective key size from parameter or name
        effective_key = k_int
        if effective_key is None:
            for sz in [15360, 7680, 4096, 3072, 2048, 1024]:
                if str(sz) in alg_clean:
                    effective_key = sz
                    break

        if effective_key is not None:
            if effective_key >= 15360:
                classical_sec_level = 256
                nist_q_level = 0
            elif effective_key >= 7680:
                classical_sec_level = 192
                nist_q_level = 0
            elif effective_key >= 3072:
                classical_sec_level = 128
                nist_q_level = 0
            elif effective_key >= 2048:
                classical_sec_level = 112
                nist_q_level = 0
            elif effective_key >= 1024:
                classical_sec_level = 80
                nist_q_level = 0
            else:
                # Misleading or sub-standard key sizes (< 1024 bits) - do not invent
                classical_sec_level = None
                nist_q_level = 0
        else:
            # Missing or unidentifiable key size for RSA
            classical_sec_level = None
            nist_q_level = 0
        return classical_sec_level, nist_q_level

    # 2b. Elliptic Curve Cryptography (ECC, ECDSA, ECDH, Ed25519, X25519)
    if any(ec in alg_clean for ec in ["ECC", "ECDSA", "ECDH", "SECP", "ED25519", "X25519", "P-256", "P-384", "P-521"]):
        if "521" in alg_clean or (k_int == 521 and "SECP" in alg_clean):
            classical_sec_level = 256
            nist_q_level = 0
        elif "384" in alg_clean or (k_int == 384 and "SECP" in alg_clean):
            classical_sec_level = 192
            nist_q_level = 0
        elif "256" in alg_clean or "ED25519" in alg_clean or "X25519" in alg_clean or (k_int == 256 and ("ECC" in alg_clean or "ECDSA" in alg_clean)):
            classical_sec_level = 128
            nist_q_level = 0
        elif k_int is not None and k_int in [256, 384, 521]:
            classical_sec_level = k_int // 2
            nist_q_level = 0
        else:
            # Generic ECC with ambiguous or misleading key size
            classical_sec_level = None
            nist_q_level = 0
        return classical_sec_level, nist_q_level

    # 2c. Symmetric Block Ciphers: AES
    if alg_clean.startswith("AES") or "AES-" in alg_clean:
        if "256" in alg_clean or k_int == 256:
            classical_sec_level = 256
            nist_q_level = 0
        elif "192" in alg_clean or k_int == 192:
            classical_sec_level = 192
            nist_q_level = 0
        elif "128" in alg_clean or k_int == 128:
            classical_sec_level = 128
            nist_q_level = 0
        else:
            # Generic AES without recognized key length (do not assume 128 if key_size is misleading or absent)
            classical_sec_level = None
            nist_q_level = 0
        return classical_sec_level, nist_q_level

    # 2d. Legacy Symmetric Ciphers: DES / 3DES
    if alg_clean in ["3DES", "TRIPLE-DES", "TDES"]:
        return 112, 0
    if alg_clean == "DES":
        return 56, 0

    # 2e. Standard Hashes (collision resistance security strength)
    if alg_clean in ["SHA-256", "SHA256", "SHA3-256"]:
        return 128, 0
    if alg_clean in ["SHA-384", "SHA384", "SHA3-384"]:
        return 192, 0
    if alg_clean in ["SHA-512", "SHA512", "SHA3-512"]:
        return 256, 0

    # 2f. Broken algorithms (MD5, SHA-1), composite, or unidentifiable algorithms
    # Do not invent classical security levels or arbitrary values
    return None, None


def _normalize_iso_datetime(val: Any) -> Optional[str]:
    """
    Safely normalizes date-time inputs into ISO-8601 strings conforming to
    CycloneDX 1.6 format: date-time.
    Returns None if missing, malformed, or unparseable.
    """
    if not val:
        return None
    val_str = str(val).strip()
    if not val_str:
        return None
    # If already conforms to standard ISO-8601 UTC representation (e.g. 2024-01-01T00:00:00Z)
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$", val_str):
        return val_str
    try:
        dt = datetime.fromisoformat(val_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        return None


def generate_cyclonedx_cbom(
    project_name: Optional[str],
    scan_id: Optional[str],
    findings: List[Dict[str, Any]],
    readiness_score: int
) -> Dict[str, Any]:
    """
    Serializes detected cryptographic assets into official CycloneDX 1.6 CBOM format.
    Ensures cryptoProperties and algorithmProperties conform strictly to the CycloneDX 1.6 specification.
    """
    components = []

    for idx, f in enumerate(findings):
        finding_id = f.get("id") or f"f_{idx}_{uuid.uuid4().hex[:8]}"
        comp_id = f"crypto-asset-{finding_id}"
        alg = f.get("algorithm") or "Unknown"
        usage = f.get("usage") or "encryption"
        hndl = bool(f.get("hndl", False))

        # Consistent Quantum Status Normalization
        raw_status = f.get("quantum_status")
        if raw_status:
            clean_status = str(raw_status).strip().lower()
            if clean_status in ["quantum_safe", "safe", "pqc"]:
                q_status = "quantum_safe"
                is_quantum_vulnerable: Optional[bool] = False
            elif clean_status in ["quantum_vulnerable", "vulnerable"]:
                q_status = "quantum_vulnerable"
                is_quantum_vulnerable = True
            elif clean_status in ["classical_weakness", "legacy", "weak"]:
                q_status = "classical_weakness"
                is_quantum_vulnerable = False
            elif clean_status in ["unknown", "unclassified", "none", "null"]:
                q_status = "unknown"
                is_quantum_vulnerable = None
            else:
                q_status = clean_status
                is_quantum_vulnerable = None
        else:
            # When quantum_status is missing, infer reliably from known algorithm names or mark unknown
            alg_upper = (alg or "").upper()
            if any(pqc in alg_upper for pqc in ["ML-KEM", "KYBER", "ML-DSA", "DILITHIUM", "FALCON", "SLH-DSA", "SPHINCS"]):
                q_status = "quantum_safe"
                is_quantum_vulnerable = False
            elif any(v in alg_upper for v in ["RSA", "ECC", "ECDSA", "ECDH", "DIFFIE-HELLMAN", "ED25519", "X25519"]) or re.search(r"\b(dh|dsa)\b", alg_upper.lower()):
                q_status = "quantum_vulnerable"
                is_quantum_vulnerable = True
            elif any(w in alg_upper for w in ["MD5", "SHA-1", "SHA1", "DES", "RC4"]):
                q_status = "classical_weakness"
                is_quantum_vulnerable = False
            else:
                q_status = "unknown"
                is_quantum_vulnerable = None

        # Map internal asset type to official CycloneDX 1.6 enum
        asset_type = _map_asset_type(f.get("asset_type"))

        # Defensible classical and quantum security levels
        key_size = f.get("key_size")
        classical_sec_level, nist_q_level = _calculate_security_strengths(
            alg, key_size, is_quantum_vulnerable is True
        )

        crypto_props: Dict[str, Any] = {
            "assetType": asset_type,
        }

        # In CycloneDX 1.6, assetType determines which nested properties object is populated.
        # cryptoProperties enforces additionalProperties: false.
        if asset_type == "algorithm":
            primitive = _map_algorithm_primitive(alg, usage)
            alg_props: Dict[str, Any] = {"primitive": primitive}
            param_set_id = _resolve_parameter_set_identifier(alg, key_size, f)
            if param_set_id:
                alg_props["parameterSetIdentifier"] = param_set_id
            alg_l = (alg or "").lower()
            if "secp256r1" in alg_l or "p-256" in alg_l:
                alg_props["curve"] = "secp256r1"
            elif "secp384r1" in alg_l or "p-384" in alg_l:
                alg_props["curve"] = "secp384r1"
            elif "secp521r1" in alg_l or "p-521" in alg_l:
                alg_props["curve"] = "secp521r1"
            elif "ed25519" in alg_l:
                alg_props["curve"] = "ed25519"
            elif "x25519" in alg_l:
                alg_props["curve"] = "x25519"
            elif f.get("curve"):
                alg_props["curve"] = str(f.get("curve"))

            if classical_sec_level is not None:
                alg_props["classicalSecurityLevel"] = classical_sec_level
            if nist_q_level is not None:
                alg_props["nistQuantumSecurityLevel"] = nist_q_level
            crypto_props["algorithmProperties"] = alg_props

        elif asset_type == "related-crypto-material":
            rcm_props: Dict[str, Any] = {}
            if key_size is not None:
                try:
                    s_val = int(key_size)
                    if s_val > 0:
                        rcm_props["size"] = s_val
                except (ValueError, TypeError):
                    pass
            raw_material = str(f.get("material_type") or f.get("asset_type") or f.get("type") or "").strip().lower()
            valid_rcm_types = {
                'private-key', 'public-key', 'secret-key', 'key', 'ciphertext',
                'signature', 'digest', 'initialization-vector', 'nonce', 'seed',
                'salt', 'shared-secret', 'tag', 'additional-data', 'password',
                'credential', 'token', 'other', 'unknown'
            }
            if raw_material in valid_rcm_types:
                rcm_props["type"] = raw_material
            elif "secret" in raw_material or "sym" in raw_material:
                rcm_props["type"] = "secret-key"
            elif "priv" in raw_material:
                rcm_props["type"] = "private-key"
            elif "pub" in raw_material:
                rcm_props["type"] = "public-key"
            elif "key" in raw_material:
                rcm_props["type"] = "key"
            elif raw_material in ["unknown", "none", ""]:
                raw_asset = str(f.get("asset_type") or "").strip().lower()
                rcm_props["type"] = "key" if "key" in raw_asset else "unknown"
            else:
                rcm_props["type"] = "other"

            mat_id = f.get("material_id") or f.get("id")
            if mat_id:
                rcm_props["id"] = str(mat_id)
            mat_fmt = f.get("material_format") or f.get("format")
            if mat_fmt:
                rcm_props["format"] = str(mat_fmt)
            valid_key_states = {'pre-activation', 'active', 'suspended', 'deactivated', 'compromised', 'destroyed'}
            mat_state = str(f.get("state") or "").strip().lower()
            if mat_state in valid_key_states:
                rcm_props["state"] = mat_state
            crypto_props["relatedCryptoMaterialProperties"] = rcm_props

        elif asset_type == "certificate":
            cert_props: Dict[str, Any] = {}
            subj = f.get("subject_name") or f.get("certificate_subject") or f.get("subject")
            if subj:
                cert_props["subjectName"] = str(subj)
            iss = f.get("issuer_name") or f.get("certificate_issuer") or f.get("issuer")
            if iss:
                cert_props["issuerName"] = str(iss)
            fmt = f.get("certificate_format") or f.get("format")
            if fmt:
                cert_props["certificateFormat"] = str(fmt)
            nvb = _normalize_iso_datetime(f.get("not_valid_before") or f.get("validity_start") or f.get("valid_from"))
            if nvb:
                cert_props["notValidBefore"] = nvb
            nva = _normalize_iso_datetime(f.get("not_valid_after") or f.get("validity_end") or f.get("valid_to"))
            if nva:
                cert_props["notValidAfter"] = nva
            ext = f.get("certificate_extension") or f.get("extension")
            if ext:
                cert_props["certificateExtension"] = str(ext)
            if cert_props:
                crypto_props["certificateProperties"] = cert_props

        elif asset_type == "protocol":
            prot_props: Dict[str, Any] = {}
            alg_l = (alg or "").lower()
            if "tls" in alg_l:
                prot_props["type"] = "tls"
                if "1.3" in alg_l or "v1.3" in alg_l:
                    prot_props["version"] = "1.3"
                elif "1.2" in alg_l or "v1.2" in alg_l:
                    prot_props["version"] = "1.2"
                elif "1.1" in alg_l or "v1.1" in alg_l:
                    prot_props["version"] = "1.1"
                elif "1.0" in alg_l or "v1.0" in alg_l:
                    prot_props["version"] = "1.0"
            elif "ssh" in alg_l:
                prot_props["type"] = "ssh"
                if "2.0" in alg_l or "2" in alg_l:
                    prot_props["version"] = "2.0"
            elif "ipsec" in alg_l:
                prot_props["type"] = "ipsec"
            elif "ike" in alg_l:
                prot_props["type"] = "ike"
            elif "sstp" in alg_l:
                prot_props["type"] = "sstp"
            elif "wpa" in alg_l:
                prot_props["type"] = "wpa"
            else:
                prot_props["type"] = "other"
            if f.get("version") and "version" not in prot_props:
                prot_props["version"] = str(f.get("version"))
            crypto_props["protocolProperties"] = prot_props

        # Preserve Keynova-specific properties using CycloneDX standard component properties
        qv_val = "true" if is_quantum_vulnerable is True else ("false" if is_quantum_vulnerable is False else "unknown")
        component_props: List[Dict[str, str]] = [
            {"name": "keynova:quantum_status", "value": str(q_status)},
            {"name": "keynova:quantum_vulnerable", "value": qv_val},
            {"name": "keynova:hndl", "value": "true" if hndl else "false"},
        ]
        if key_size is not None:
            component_props.append({"name": "keynova:key_size", "value": str(key_size)})

        file_path = f.get("file_path")
        line_start = f.get("line_start")
        line_end = f.get("line_end")

        if file_path:
            component_props.append({"name": "keynova:file_path", "value": str(file_path)})
        if line_start is not None:
            component_props.append({"name": "keynova:line_start", "value": str(line_start)})
        if line_end is not None:
            component_props.append({"name": "keynova:line_end", "value": str(line_end)})
        if f.get("rule_id"):
            component_props.append({"name": "keynova:rule_id", "value": str(f.get("rule_id"))})

        comp_dict: Dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": comp_id,
            "name": alg,
            "version": str(key_size) if key_size is not None else "standard",
            "description": str(f.get("evidence", "") or ""),
            "cryptoProperties": crypto_props,
            "properties": component_props,
        }

        # CycloneDX 1.6 evidence.occurrences for source location
        if file_path:
            occ: Dict[str, Any] = {"location": str(file_path).replace("\\", "/")}
            if line_start is not None:
                try:
                    l_val = int(line_start)
                    if l_val >= 0:
                        occ["line"] = l_val
                except (ValueError, TypeError):
                    pass
            if f.get("code_snippet"):
                occ["additionalContext"] = str(f.get("code_snippet"))
            comp_dict["evidence"] = {"occurrences": [occ]}

        components.append(comp_dict)

    safe_project_name = project_name or "Cryptographic Service"
    safe_scan_id = scan_id or str(uuid.uuid4())
    scan_ver = safe_scan_id[:8] if len(safe_scan_id) >= 8 else safe_scan_id

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "Keynova Post-Quantum Readiness Engine",
                        "version": "1.0.0"
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": safe_project_name,
                "version": f"scan-{scan_ver}"
            },
            "properties": [
                {"name": "keynova:readiness_score", "value": str(readiness_score)},
                {"name": "keynova:cbom_version", "value": "1.6"}
            ]
        },
        "components": components
    }


def serialize_cbom_json(cbom: Dict[str, Any], indent: int = 2) -> str:
    """
    Serializes a CycloneDX CBOM dictionary into human-readable, pretty-printed JSON
    with standard line breaks and indentation.
    """
    return json.dumps(cbom, indent=indent)

