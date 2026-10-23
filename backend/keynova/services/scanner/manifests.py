import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any

VULNERABLE_PACKAGES = {
    "pycryptodome": {
        "severity": "low",
        "algorithm": "DES/RSA/RC4",
        "usage": "dependency",
        "evidence": "PyCryptodome exposes legacy ciphers and non-PQC primitives without quantum agility.",
        "quantum_status": "quantum_vulnerable"
    },
    "pycrypto": {
        "severity": "high",
        "algorithm": "Legacy Ciphers",
        "usage": "dependency",
        "evidence": "Unmaintained crypto library containing unpatched CVEs and deprecated primitives.",
        "quantum_status": "quantum_vulnerable"
    },
    "crypto-js": {
        "severity": "medium",
        "algorithm": "MD5/SHA1/AES",
        "usage": "client_encryption",
        "evidence": "Browser JS cryptographic library lacking post-quantum algorithms.",
        "quantum_status": "quantum_vulnerable"
    }
}

def scan_manifest_file(file_path: Path, relative_to: Path) -> List[Dict[str, Any]]:
    findings = []
    rel_path = str(file_path.relative_to(relative_to))
    filename = file_path.name.lower()

    try:
        content = file_path.read_text(encoding="utf-8")
        if filename in ["requirements.txt", "requirements-dev.txt"]:
            for idx, line in enumerate(content.splitlines(), start=1):
                clean = line.strip().lower()
                if not clean or clean.startswith("#"):
                    continue
                pkg_name = clean.split("==")[0].split(">=")[0].split("<=")[0].strip()
                if pkg_name in VULNERABLE_PACKAGES:
                    meta = VULNERABLE_PACKAGES[pkg_name]
                    fp_raw = f"{rel_path}:{pkg_name}:dependency"
                    fingerprint = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()
                    findings.append({
                        "fingerprint": fingerprint,
                        "file_path": rel_path,
                        "line_start": idx,
                        "line_end": idx,
                        "code_snippet": line.strip(),
                        "asset_type": "manifest",
                        "algorithm": meta["algorithm"],
                        "usage": meta["usage"],
                        "library": pkg_name,
                        "key_size": None,
                        "severity": meta["severity"],
                        "quantum_status": meta["quantum_status"],
                        "hndl": False,
                        "confidence": 1.0,
                        "rule_id": f"DEP_{pkg_name.upper()}",
                        "evidence": meta["evidence"]
                    })

        elif filename == "package.json":
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg_name, ver in deps.items():
                if pkg_name.lower() in VULNERABLE_PACKAGES:
                    meta = VULNERABLE_PACKAGES[pkg_name.lower()]
                    fp_raw = f"{rel_path}:{pkg_name}:dependency"
                    fingerprint = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()
                    findings.append({
                        "fingerprint": fingerprint,
                        "file_path": rel_path,
                        "line_start": 1,
                        "line_end": 1,
                        "code_snippet": f'"{pkg_name}": "{ver}"',
                        "asset_type": "manifest",
                        "algorithm": meta["algorithm"],
                        "usage": meta["usage"],
                        "library": pkg_name,
                        "key_size": None,
                        "severity": meta["severity"],
                        "quantum_status": meta["quantum_status"],
                        "hndl": False,
                        "confidence": 1.0,
                        "rule_id": f"DEP_{pkg_name.upper()}",
                        "evidence": meta["evidence"]
                    })
    except Exception:
        pass

    return findings
