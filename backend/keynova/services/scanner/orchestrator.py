from pathlib import Path
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any

from keynova.core.database import Scan, Finding, ScanComparison
from keynova.services.scanner.python_ast import scan_python_file
from keynova.services.scanner.manifests import scan_manifest_file

try:
    from keynova.services.intelligence.scoring import calculate_readiness_score
except ImportError:
    def calculate_readiness_score(
        findings: List[Dict[str, Any]],
        total_files: int = 0,
        scanned_files: int = 0
    ) -> Dict[str, Any]:
        SEVERITY_WEIGHTS = {
            "critical": 25.0,
            "high": 12.0,
            "medium": 5.0,
            "low": 2.0,
            "quantum_safe": 0.0
        }
        total_penalty = 0.0
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "quantum_safe": 0}
        hndl_count = 0

        for f in findings:
            sev = f.get("severity", "low").lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            weight = SEVERITY_WEIGHTS.get(sev, 2.0)
            h_mult = 1.4 if f.get("hndl", False) else 1.0
            conf = f.get("confidence", 1.0)
            total_penalty += weight * h_mult * conf
            if f.get("hndl", False):
                hndl_count += 1

        d_risk = min(100.0, total_penalty)
        coverage_ratio = 1.0 if total_files == 0 else (scanned_files / total_files)
        c_factor = 0.5 + 0.5 * coverage_ratio
        readiness_score = round(max(0.0, 100.0 - d_risk) * c_factor)

        return {
            "readiness_score": readiness_score,
            "coverage_percent": round(coverage_ratio * 100.0, 1),
            "total_files": total_files,
            "scanned_files": scanned_files,
            "severity_counts": sev_counts,
            "hndl_count": hndl_count,
            "total_penalty": total_penalty
        }

try:
    from keynova.services.intelligence.diff import compare_scans
except ImportError:
    def compare_scans(
        baseline_findings: List[Dict[str, Any]],
        target_findings: List[Dict[str, Any]],
        baseline_score: int,
        target_score: int
    ) -> Dict[str, Any]:
        base_fp = {f["fingerprint"] for f in baseline_findings}
        targ_fp = {f["fingerprint"] for f in target_findings}

        resolved_fps = base_fp - targ_fp
        added_fps = targ_fp - base_fp
        unchanged_count = len(base_fp.intersection(targ_fp))

        resolved = [f for f in baseline_findings if f["fingerprint"] in resolved_fps]
        added = [f for f in target_findings if f["fingerprint"] in added_fps]
        delta = target_score - baseline_score

        if len(target_findings) == 0:
            status = "verified_clean"
        elif len(added) > 0 and target_score < baseline_score:
            status = "regression_detected"
        else:
            status = "partial_remediation"

        return {
            "resolved_count": len(resolved),
            "added_count": len(added),
            "unchanged_count": unchanged_count,
            "readiness_delta": delta,
            "verification_status": status,
            "resolved_findings": resolved,
            "added_findings": added
        }

IGNORE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

def execute_scan(
    db: Session,
    scan_id: str,
    source_path: Path,
    baseline_scan_id: Optional[str] = None
) -> Scan:
    """Orchestrates source code traversal, AST analysis, scoring, and DB persistence."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None

    scan.status = "analyzing"
    db.commit()

    all_files = []
    scanned_files = []
    findings_data: List[Dict[str, Any]] = []

    # 1. Directory Traversal
    for path in source_path.rglob("*"):
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if path.is_file():
            all_files.append(path)
            
            # 2. Python AST Analysis
            if path.suffix == ".py":
                scanned_files.append(path)
                py_findings = scan_python_file(path, relative_to=source_path)
                for f in py_findings:
                    findings_data.append(f.to_dict())

            # 3. Dependency Manifest Analysis
            elif path.name.lower() in ["requirements.txt", "package.json"]:
                scanned_files.append(path)
                manifest_findings = scan_manifest_file(path, relative_to=source_path)
                findings_data.extend(manifest_findings)

    total_count = len(all_files)
    scanned_count = len(scanned_files)

    # 4. Calculate Keynova Readiness Index
    score_report = calculate_readiness_score(
        findings=findings_data,
        total_files=total_count,
        scanned_files=scanned_count
    )

    # 5. Persist Findings to Database
    for f in findings_data:
        finding_obj = Finding(
            scan_id=scan.id,
            fingerprint=f["fingerprint"],
            file_path=f["file_path"],
            line_start=f["line_start"],
            line_end=f["line_end"],
            code_snippet=f["code_snippet"],
            asset_type=f["asset_type"],
            algorithm=f["algorithm"],
            usage=f["usage"],
            library=f.get("library"),
            key_size=f.get("key_size"),
            severity=f["severity"],
            quantum_status=f["quantum_status"],
            hndl=f["hndl"],
            confidence=f["confidence"],
            rule_id=f["rule_id"],
            evidence=f["evidence"],
            metadata_json={}
        )
        db.add(finding_obj)

    # 6. Update Scan Record
    scan.status = "completed"
    scan.total_files = total_count
    scan.scanned_files = scanned_count
    scan.readiness_score = score_report["readiness_score"]
    scan.coverage_percent = score_report["coverage_percent"]
    scan.critical_count = score_report["severity_counts"]["critical"]
    scan.high_count = score_report["severity_counts"]["high"]
    scan.medium_count = score_report["severity_counts"]["medium"]
    scan.low_count = score_report["severity_counts"]["low"]
    scan.quantum_safe_count = score_report["severity_counts"]["quantum_safe"]
    scan.hndl_count = score_report["hndl_count"]
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()

    # 7. Compare with Baseline Scan if provided
    if baseline_scan_id:
        baseline_scan = db.query(Scan).filter(Scan.id == baseline_scan_id).first()
        if baseline_scan:
            base_findings = [
                {
                    "fingerprint": bf.fingerprint,
                    "file_path": bf.file_path,
                    "algorithm": bf.algorithm,
                    "usage": bf.usage,
                    "severity": bf.severity
                }
                for bf in baseline_scan.findings
            ]
            targ_findings = [
                {
                    "fingerprint": tf.fingerprint,
                    "file_path": tf.file_path,
                    "algorithm": tf.algorithm,
                    "usage": tf.usage,
                    "severity": tf.severity
                }
                for tf in scan.findings
            ]
            comparison = compare_scans(
                baseline_findings=base_findings,
                target_findings=targ_findings,
                baseline_score=baseline_scan.readiness_score,
                target_score=scan.readiness_score
            )
            comp_record = ScanComparison(
                baseline_scan_id=baseline_scan.id,
                target_scan_id=scan.id,
                resolved_count=comparison["resolved_count"],
                added_count=comparison["added_count"],
                unchanged_count=comparison["unchanged_count"],
                readiness_delta=comparison["readiness_delta"],
                verification_status=comparison["verification_status"],
                resolved_findings=comparison["resolved_findings"],
                added_findings=comparison["added_findings"]
            )
            db.add(comp_record)
            db.commit()

    return scan
