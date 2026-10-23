import time
from typing import Dict, Any

# Canonical algorithm metadata according to NIST FIPS 203, FIPS 204, and ANSI/PKCS standards
SUPPORTED_ALGORITHMS = {
    "ML-KEM-768": {
        "nist_standard": "FIPS 203 (Module-Lattice KEM)",
        "canonical_name": "ML-KEM-768",
        "family": "kem",
        "security_level": 3,
        "public_key_bytes": 1184,
        "ciphertext_bytes": 1088,
        "operations": ["Key Generation", "Encapsulation", "Decapsulation"]
    },
    "ML-KEM-1024": {
        "nist_standard": "FIPS 203 (Module-Lattice KEM - High Security)",
        "canonical_name": "ML-KEM-1024",
        "family": "kem",
        "security_level": 5,
        "public_key_bytes": 1568,
        "ciphertext_bytes": 1568,
        "operations": ["Key Generation", "Encapsulation", "Decapsulation"]
    },
    "ML-DSA-65": {
        "nist_standard": "FIPS 204 (Module-Lattice Digital Signature)",
        "canonical_name": "ML-DSA-65",
        "family": "sign",
        "security_level": 3,
        "public_key_bytes": 1952,
        "ciphertext_bytes": 3309,  # Signature payload size
        "operations": ["Key Generation", "Signing", "Verification"]
    },
    "RSA-2048": {
        "nist_standard": "PKCS#1 v2.2 (Legacy Classical)",
        "canonical_name": "RSA-2048",
        "family": "classical_enc",
        "security_level": 1,
        "public_key_bytes": 270,   # Standard X.509 SubjectPublicKeyInfo DER
        "ciphertext_bytes": 256,   # 2048-bit modulus output
        "operations": ["Key Generation", "Encryption", "Decryption"]
    },
    "ECDSA-P256": {
        "nist_standard": "FIPS 186-5 (Legacy Classical)",
        "canonical_name": "ECDSA-P256",
        "family": "classical_sign",
        "security_level": 1,
        "public_key_bytes": 65,    # Uncompressed SEC1 point (0x04 || X || Y)
        "ciphertext_bytes": 64,    # IEEE P1363 (r || s) signature
        "operations": ["Key Generation", "Signing", "Verification"]
    }
}

def normalize_algorithm_name(name: str) -> str:
    """Matches user input against canonical supported algorithm names."""
    if not name or not isinstance(name, str):
        raise ValueError("Algorithm name must be a non-empty string.")

    clean = name.strip().upper().replace("_", "-").replace(" ", "-")
    alias_map = {
        "ML-KEM-768": "ML-KEM-768",
        "MLKEM768": "ML-KEM-768",
        "KYBER-768": "ML-KEM-768",
        "KYBER768": "ML-KEM-768",
        "ML-KEM-1024": "ML-KEM-1024",
        "MLKEM1024": "ML-KEM-1024",
        "KYBER-1024": "ML-KEM-1024",
        "KYBER1024": "ML-KEM-1024",
        "ML-DSA-65": "ML-DSA-65",
        "MLDSA65": "ML-DSA-65",
        "DILITHIUM3": "ML-DSA-65",
        "DILITHIUM-3": "ML-DSA-65",
        "RSA-2048": "RSA-2048",
        "RSA2048": "RSA-2048",
        "RSA": "RSA-2048",
        "ECDSA-P256": "ECDSA-P256",
        "ECDSAP256": "ECDSA-P256",
        "P256": "ECDSA-P256",
        "SECP256R1": "ECDSA-P256",
        "ECDSA-SECP256R1": "ECDSA-P256"
    }

    if clean in alias_map:
        return alias_map[clean]

    supported = sorted(SUPPORTED_ALGORITHMS.keys())
    raise ValueError(
        f"Unsupported algorithm '{name}'. Supported algorithms are: {', '.join(supported)}."
    )

def _benchmark_kem(module, iterations: int) -> Dict[str, float]:
    """Measures keygen, encaps, and decaps for a NIST ML-KEM module."""
    # 1. Key Generation
    pks = []
    sks = []
    t0 = time.perf_counter_ns()
    for _ in range(iterations):
        pk, sk = module.keygen()
        pks.append(pk)
        sks.append(sk)
    t1 = time.perf_counter_ns()
    avg_keygen_us = (t1 - t0) / (iterations * 1000.0)

    # 2. Encapsulation
    cts = []
    t2 = time.perf_counter_ns()
    for i in range(iterations):
        ct, ss = module.encaps(pks[i])
        cts.append(ct)
    t3 = time.perf_counter_ns()
    avg_encap_us = (t3 - t2) / (iterations * 1000.0)

    # 3. Decapsulation
    t4 = time.perf_counter_ns()
    for i in range(iterations):
        module.decaps(sks[i], cts[i])
    t5 = time.perf_counter_ns()
    avg_decap_us = (t5 - t4) / (iterations * 1000.0)

    return {
        "avg_keygen_latency_us": round(avg_keygen_us, 1),
        "avg_encap_latency_us": round(avg_encap_us, 1),
        "avg_decap_latency_us": round(avg_decap_us, 1)
    }

def _benchmark_ml_dsa_65(module, iterations: int) -> Dict[str, float]:
    """Measures keygen, sign, and verify for NIST ML-DSA-65."""
    pks = []
    sks = []
    t0 = time.perf_counter_ns()
    for _ in range(iterations):
        pk, sk = module.keygen()
        pks.append(pk)
        sks.append(sk)
    t1 = time.perf_counter_ns()
    avg_keygen_us = (t1 - t0) / (iterations * 1000.0)

    msg = b"Keynova digital signature verification test payload"
    sigs = []
    t2 = time.perf_counter_ns()
    for i in range(iterations):
        sig = module.sign(sks[i], msg)
        sigs.append(sig)
    t3 = time.perf_counter_ns()
    avg_sign_us = (t3 - t2) / (iterations * 1000.0)

    t4 = time.perf_counter_ns()
    for i in range(iterations):
        module.verify(pks[i], msg, sigs[i])
    t5 = time.perf_counter_ns()
    avg_verify_us = (t5 - t4) / (iterations * 1000.0)

    return {
        "avg_keygen_latency_us": round(avg_keygen_us, 1),
        "avg_encap_latency_us": round(avg_sign_us, 1),   # Mapped to sign for schema consistency
        "avg_decap_latency_us": round(avg_verify_us, 1) # Mapped to verify for schema consistency
    }

def _benchmark_rsa_2048(iterations: int) -> Dict[str, float]:
    """Measures keygen, OAEP encrypt, and decrypt for classical RSA-2048."""
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes

    # RSA keygen is computationally heavy (~20-80ms per key); sample up to min(iterations, 3)
    keygen_runs = min(iterations, 3)
    t0 = time.perf_counter_ns()
    keys = [
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for _ in range(keygen_runs)
    ]
    t1 = time.perf_counter_ns()
    avg_keygen_us = (t1 - t0) / (keygen_runs * 1000.0)

    priv_key = keys[0]
    pub_key = priv_key.public_key()
    pad = padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    msg = b"Sensitive payment token payload."

    cts = []
    t2 = time.perf_counter_ns()
    for _ in range(iterations):
        cts.append(pub_key.encrypt(msg, pad))
    t3 = time.perf_counter_ns()
    avg_enc_us = (t3 - t2) / (iterations * 1000.0)

    t4 = time.perf_counter_ns()
    for ct in cts:
        priv_key.decrypt(ct, pad)
    t5 = time.perf_counter_ns()
    avg_dec_us = (t5 - t4) / (iterations * 1000.0)

    return {
        "avg_keygen_latency_us": round(avg_keygen_us, 1),
        "avg_encap_latency_us": round(avg_enc_us, 1),
        "avg_decap_latency_us": round(avg_dec_us, 1)
    }

def _benchmark_ecdsa_p256(iterations: int) -> Dict[str, float]:
    """Measures keygen, ECDSA sign, and verify for SECP256R1."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes

    t0 = time.perf_counter_ns()
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(iterations)]
    t1 = time.perf_counter_ns()
    avg_keygen_us = (t1 - t0) / (iterations * 1000.0)

    priv_key = keys[0]
    pub_key = priv_key.public_key()
    msg = b"Transaction authorization signature"

    sigs = []
    t2 = time.perf_counter_ns()
    for _ in range(iterations):
        sigs.append(priv_key.sign(msg, ec.ECDSA(hashes.SHA256())))
    t3 = time.perf_counter_ns()
    avg_sign_us = (t3 - t2) / (iterations * 1000.0)

    t4 = time.perf_counter_ns()
    for sig in sigs:
        pub_key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    t5 = time.perf_counter_ns()
    avg_verify_us = (t5 - t4) / (iterations * 1000.0)

    return {
        "avg_keygen_latency_us": round(avg_keygen_us, 1),
        "avg_encap_latency_us": round(avg_sign_us, 1),   # Mapped to sign for schema consistency
        "avg_decap_latency_us": round(avg_verify_us, 1) # Mapped to verify for schema consistency
    }

def benchmark_algorithm(algorithm: str, iterations: int = 100) -> Dict[str, Any]:
    """
    Executes live cryptographic benchmarking for supported NIST PQC and classical algorithms.
    
    Validates input parameters strictly and executes genuine C/Python cryptographic operations,
    returning actual measured microsecond timings and byte sizes.
    """
    canonical_name = normalize_algorithm_name(algorithm)

    if not isinstance(iterations, int) or iterations < 1 or iterations > 1000:
        raise ValueError("iterations must be an integer between 1 and 1000.")

    meta = SUPPORTED_ALGORITHMS[canonical_name]

    if canonical_name == "ML-KEM-768":
        import pqcrypto.kem.ml_kem_768 as kem_mod
        timings = _benchmark_kem(kem_mod, iterations)
    elif canonical_name == "ML-KEM-1024":
        import pqcrypto.kem.ml_kem_1024 as kem_mod
        timings = _benchmark_kem(kem_mod, iterations)
    elif canonical_name == "ML-DSA-65":
        import pqcrypto.sign.ml_dsa_65 as dsa_mod
        timings = _benchmark_ml_dsa_65(dsa_mod, iterations)
    elif canonical_name == "RSA-2048":
        timings = _benchmark_rsa_2048(iterations)
    elif canonical_name == "ECDSA-P256":
        timings = _benchmark_ecdsa_p256(iterations)
    else:
        raise ValueError(f"Algorithm '{canonical_name}' has no registered execution harness.")

    return {
        "algorithm": canonical_name,
        "nist_standard": meta["nist_standard"],
        "iterations": iterations,
        "avg_keygen_latency_us": timings["avg_keygen_latency_us"],
        "avg_encap_latency_us": timings["avg_encap_latency_us"],
        "avg_decap_latency_us": timings["avg_decap_latency_us"],
        "public_key_bytes": meta["public_key_bytes"],
        "ciphertext_bytes": meta["ciphertext_bytes"],
        "security_level": meta["security_level"]
    }
