from typing import List, Dict, Any

SEVERITY_WEIGHTS = {
    "critical": 25.0,
    "high": 12.0,
    "medium": 5.0,
    "low": 2.0,
    "quantum_safe": 0.0
}

def calculate_readiness_score(
    findings: List[Dict[str, Any]],
    total_files: int,
    scanned_files: int
) -> Dict[str, Any]:
    """
    Implements the deterministic Keynova Readiness Index formula:
    R = round( max(0, 100 - D_risk) * C )
    where:
      D_risk = min(100, sum( Weight(sev_i) * H_i * conf_i ))
      C = 0.5 + 0.5 * (scanned_files / total_files)
    """
    total_files = max(1, total_files)
    scanned_files = min(total_files, max(1, scanned_files))

    # 1. Coverage Factor: C = 0.5 + 0.5 * (scanned / total)
    coverage_ratio = scanned_files / total_files
    coverage_factor = 0.5 + 0.5 * coverage_ratio
    coverage_percent = round(coverage_ratio * 100.0, 2)

    # 2. Risk Density Penalty: D_risk = min(100, sum( Weight * HNDL * Confidence ))
    total_penalty = 0.0
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "quantum_safe": 0
    }
    hndl_count = 0

    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["low"] += 1

        weight = SEVERITY_WEIGHTS.get(sev, 2.0)
        hndl_mult = 1.4 if f.get("hndl", False) else 1.0
        if f.get("hndl", False):
            hndl_count += 1

        conf = float(f.get("confidence", 1.0))
        penalty = weight * hndl_mult * conf
        total_penalty += penalty

    capped_penalty = min(100.0, total_penalty)
    base_score = max(0.0, 100.0 - capped_penalty)
    final_score = int(round(base_score * coverage_factor))

    return {
        "readiness_score": final_score,
        "coverage_percent": coverage_percent,
        "total_files": total_files,
        "scanned_files": scanned_files,
        "severity_counts": severity_counts,
        "hndl_count": hndl_count,
        "total_penalty": round(capped_penalty, 2)
    }
