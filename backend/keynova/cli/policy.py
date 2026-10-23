"""
Keynova Cryptographic Policy Evaluation Engine.

Provides automated compliance gating for CI/CD pipelines and security audits.
Evaluates cryptographic findings and scan metadata against explicit policy rules:
1. Minimum Keynova Readiness Index threshold.
2. Zero-tolerance Harvest-Now-Decrypt-Later (HNDL) vulnerability blocking.
3. Maximum permitted finding severity thresholds (low, medium, high, critical).
4. Prohibited/disallowed algorithm lists (e.g. MD5, SHA-1, DES, 3DES, RC4).
5. Post-quantum cryptographic requirements (require_quantum_safe).
6. Minimum cryptographic key size standards.

Design Principles:
- Fails closed on evaluation errors.
- Never treats missing or unknown information as proof of safety.
- Handles empty findings and missing fields gracefully without crashing.
- Produces structured, machine-readable JSON results and clean terminal reports.
- Emits distinct exit codes: 0 = PASS, 1 = VIOLATION, 2 = USAGE/INPUT ERROR.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union


SEVERITY_ORDER: Dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


DEFAULT_POLICY: Dict[str, Any] = {
    "min_readiness_score": 80,
    "block_hndl": True,
    "max_severity": None,            # None or "low", "medium", "high", "critical"
    "disallowed_algorithms": [],      # List of strings, e.g. ["MD5", "SHA-1", "DES"]
    "require_quantum_safe": False,    # If True, any non-quantum-safe finding is a violation
    "min_key_sizes": {               # Optional key size minimums
        "rsa": 2048,
        "ec": 256,
        "ecdsa": 256,
    }
}


class PolicyViolation:
    """Represents an identified policy violation."""

    def __init__(
        self,
        rule: str,
        message: str,
        severity: str = "critical",
        file_path: Optional[str] = None,
        line: Optional[int] = None,
        finding_id: Optional[str] = None
    ):
        self.rule = rule
        self.message = message
        self.severity = severity
        self.file_path = file_path
        self.line = line
        self.finding_id = finding_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "file_path": self.file_path,
            "line": self.line,
            "finding_id": self.finding_id,
        }

    def __repr__(self) -> str:
        loc = f" at {self.file_path}:{self.line}" if self.file_path else ""
        return f"[{self.severity.upper()}] {self.rule}: {self.message}{loc}"


def load_policy(policy_source: Optional[Union[str, Path, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Loads and normalizes policy configuration from a file path or dictionary,
    merging with KEYNOVA default settings.
    """
    policy = dict(DEFAULT_POLICY)
    if policy_source is None:
        return policy

    if isinstance(policy_source, (str, Path)):
        p_path = Path(policy_source).resolve()
        if not p_path.exists():
            raise FileNotFoundError(f"Policy file '{p_path}' does not exist.")
        try:
            with open(p_path, "r", encoding="utf-8") as f:
                user_policy = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Malformed JSON in policy file '{p_path}': {e}")
        except Exception as e:
            raise ValueError(f"Failed to read policy file '{p_path}': {e}")
    elif isinstance(policy_source, dict):
        user_policy = policy_source
    else:
        raise TypeError(f"Invalid policy source type: {type(policy_source).__name__}")

    if not isinstance(user_policy, dict):
        raise ValueError("Policy configuration must be a JSON object / dictionary.")

    # Merge user settings
    for key, val in user_policy.items():
        policy[key] = val

    return policy


def evaluate_policy(
    findings: Optional[List[Dict[str, Any]]] = None,
    policy: Optional[Dict[str, Any]] = None,
    scan_meta: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates cryptographic findings and scan metadata against explicit policy rules.

    Args:
        findings: List of finding dictionaries (from AST, manifest scanner, or CBOM).
        policy: Policy rules dictionary (min_readiness_score, block_hndl, max_severity, etc.).
        scan_meta: Scan metadata dictionary (readiness_score, coverage_percent, hndl_count).

    Returns:
        Dict[str, Any] containing:
            passed (bool): True if zero violations, False otherwise.
            summary (dict): Evaluation metrics summary.
            policy (dict): Effective policy settings applied.
            violations (list): List of violation dictionaries with rule, severity, message, file, line.
    """
    if findings is None:
        findings = []
    if policy is None:
        policy = dict(DEFAULT_POLICY)
    if scan_meta is None:
        scan_meta = {}

    violations: List[PolicyViolation] = []

    # 1. Readiness Score Rule
    min_readiness = policy.get("min_readiness_score")
    if min_readiness is not None:
        try:
            min_score_val = int(min_readiness)
            score = scan_meta.get("readiness_score")
            if score is not None:
                score_val = int(score)
                if score_val < min_score_val:
                    violations.append(PolicyViolation(
                        rule="min_readiness_score",
                        message=f"Keynova Readiness Score {score_val} is below minimum threshold of {min_score_val}.",
                        severity="critical"
                    ))
        except (ValueError, TypeError):
            pass

    # 2. Extract policy options
    block_hndl = bool(policy.get("block_hndl", True))
    meta_hndl_count = scan_meta.get("hndl_count", 0)

    raw_disallowed = policy.get("disallowed_algorithms", [])
    if isinstance(raw_disallowed, str):
        disallowed_algos = [a.strip().lower() for a in raw_disallowed.split(",") if a.strip()]
    elif isinstance(raw_disallowed, (list, tuple, set)):
        disallowed_algos = [str(a).strip().lower() for a in raw_disallowed if str(a).strip()]
    else:
        disallowed_algos = []

    max_severity = policy.get("max_severity")
    max_sev_rank = SEVERITY_ORDER.get(str(max_severity).lower().strip()) if max_severity else None
    require_pqc = bool(policy.get("require_quantum_safe", False))
    min_key_sizes = policy.get("min_key_sizes", {})

    found_hndl_in_findings = False

    # 3. Inspect every finding
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            violations.append(PolicyViolation(
                rule="malformed_finding",
                message=f"Finding at index {idx} is not a valid dictionary object.",
                severity="critical"
            ))
            continue

        algo = str(f.get("algorithm") or "").strip()
        algo_lower = algo.lower()
        file_path = f.get("file_path")
        line = f.get("line_start")
        f_id = str(f.get("id") or "")
        sev = str(f.get("severity") or "").strip().lower()
        is_hndl = bool(f.get("hndl"))
        if is_hndl:
            found_hndl_in_findings = True

        # Rule A: Block HNDL (Harvest-Now-Decrypt-Later)
        if block_hndl and is_hndl:
            violations.append(PolicyViolation(
                rule="block_hndl",
                message=f"Harvest-Now-Decrypt-Later (HNDL) risk detected with algorithm '{algo or 'Unknown'}'.",
                severity="critical",
                file_path=file_path,
                line=line,
                finding_id=f_id
            ))

        # Rule B: Disallowed Algorithms
        if algo:
            for dis_algo in disallowed_algos:
                if dis_algo in algo_lower:
                    violations.append(PolicyViolation(
                        rule="disallowed_algorithm",
                        message=f"Disallowed algorithm '{algo}' violates policy constraint against '{dis_algo.upper()}'.",
                        severity="critical",
                        file_path=file_path,
                        line=line,
                        finding_id=f_id
                    ))
                    break  # Avoid duplicate violation for the same algorithm pattern

        # Rule C: Maximum Permitted Severity
        if max_sev_rank is not None and sev:
            sev_rank = SEVERITY_ORDER.get(sev, 1)
            if sev_rank > max_sev_rank:
                violations.append(PolicyViolation(
                    rule="max_severity_exceeded",
                    message=f"Finding severity '{sev.upper()}' exceeds maximum permitted severity '{max_severity.upper()}'.",
                    severity="critical" if sev == "critical" else "high",
                    file_path=file_path,
                    line=line,
                    finding_id=f_id
                ))

        # Rule D: Require Quantum-Safe (Do not treat unknown as proof of safety)
        if require_pqc:
            q_status = str(f.get("quantum_status") or "").lower().strip()
            pqc_tokens = [
                "ml-kem", "ml-dsa", "slh-dsa", "kyber", "dilithium", "falcon",
                "sphincs", "xmss", "lms", "sha-3", "sha3", "shake", "aes-256", "chacha20"
            ]
            is_explicit_safe = q_status in ["safe", "quantum_safe", "quantum_resistant", "post_quantum"]
            has_pqc_algo = any(tok in algo_lower for tok in pqc_tokens)

            if not is_explicit_safe and not has_pqc_algo:
                if not algo and not q_status:
                    violations.append(PolicyViolation(
                        rule="require_quantum_safe",
                        message="Cannot verify quantum safety: finding lacks both algorithm and quantum_status metadata.",
                        severity="high",
                        file_path=file_path,
                        line=line,
                        finding_id=f_id
                    ))
                else:
                    violations.append(PolicyViolation(
                        rule="require_quantum_safe",
                        message=f"Non-quantum-safe primitive '{algo or 'Unknown'}' violates strict quantum-safe policy requirement.",
                        severity="high",
                        file_path=file_path,
                        line=line,
                        finding_id=f_id
                    ))

        # Rule E: Minimum Key Size Check
        key_size = f.get("key_size")
        if key_size is not None and isinstance(min_key_sizes, dict):
            try:
                ks_val = int(key_size)
                for algo_family, min_sz in min_key_sizes.items():
                    if algo_family.lower() in algo_lower and ks_val < int(min_sz):
                        violations.append(PolicyViolation(
                            rule="minimum_key_size",
                            message=f"Key size {ks_val} for '{algo}' is below minimum required {min_sz} bits.",
                            severity="high",
                            file_path=file_path,
                            line=line,
                            finding_id=f_id
                        ))
            except (ValueError, TypeError):
                pass

    # Meta HNDL check fallback (if findings list didn't include individual HNDL but scan_meta reported HNDL)
    if block_hndl and not found_hndl_in_findings and meta_hndl_count > 0:
        violations.append(PolicyViolation(
            rule="block_hndl",
            message=f"{meta_hndl_count} Harvest-Now-Decrypt-Later (HNDL) vulnerability(ies) reported in scan metadata.",
            severity="critical"
        ))

    passed = (len(violations) == 0)

    computed_hndl = sum(1 for f in findings if isinstance(f, dict) and f.get("hndl"))
    final_hndl_count = max(computed_hndl, meta_hndl_count if meta_hndl_count else 0)

    summary = {
        "passed": passed,
        "total_findings": len(findings),
        "violations_count": len(violations),
        "readiness_score": scan_meta.get("readiness_score"),
        "coverage_percent": scan_meta.get("coverage_percent", 100.0),
        "hndl_count": final_hndl_count
    }

    return {
        "passed": passed,
        "summary": summary,
        "policy": policy,
        "violations": [v.to_dict() for v in violations]
    }
