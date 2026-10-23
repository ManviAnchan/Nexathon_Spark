from typing import List, Dict, Any

def compare_scans(
    baseline_findings: List[Dict[str, Any]],
    target_findings: List[Dict[str, Any]],
    baseline_score: int,
    target_score: int
) -> Dict[str, Any]:
    """
    Computes set operations across finding fingerprints to verify remediation.
    """
    base_map = {f["fingerprint"]: f for f in baseline_findings}
    targ_map = {f["fingerprint"]: f for f in target_findings}

    base_fps = set(base_map.keys())
    targ_fps = set(targ_map.keys())

    resolved_fps = base_fps - targ_fps
    added_fps = targ_fps - base_fps
    unchanged_fps = base_fps & targ_fps

    resolved = [base_map[fp] for fp in resolved_fps]
    added = [targ_map[fp] for fp in added_fps]

    readiness_delta = target_score - baseline_score

    if len(target_findings) == 0:
        status = "verified_clean"
    elif len(added) > 0 and readiness_delta < 0:
        status = "regression_detected"
    else:
        status = "partial_remediation"

    return {
        "resolved_count": len(resolved),
        "added_count": len(added),
        "unchanged_count": len(unchanged_fps),
        "readiness_delta": readiness_delta,
        "verification_status": status,
        "resolved_findings": resolved,
        "added_findings": added
    }
