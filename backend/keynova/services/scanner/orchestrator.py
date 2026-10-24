import sys
from pathlib import Path

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from datetime import datetime, timezone
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any, Sequence, Union

from keynova.core.database import Scan, Finding, ScanComparison
from keynova.services.scanner.python_ast import scan_python_file
from keynova.services.scanner.manifests import scan_manifest_file
from keynova.services.scanner.diff_filter import filter_crypto_affected_files, get_git_changed_files
from keynova.services.cache.ast_cache import get_ast_cache

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
    baseline_scan_id: Optional[str] = None,
    incremental: bool = False
) -> Any:
    """Orchestrates source code traversal, AST analysis, scoring, and DB persistence."""
    scan: Any = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None

    scan.status = "analyzing"
    db.commit()

    all_files: List[Path] = []
    scanned_files: List[Path] = []
    findings_data: List[Dict[str, Any]] = []
    total_count: int = 0
    scanned_count: int = 0
    score_report: Dict[str, Any] = {
        "readiness_score": 100,
        "coverage_percent": 100.0,
        "severity_counts": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "quantum_safe": 0
        },
        "hndl_count": 0,
        "total_penalty": 0.0
    }

    # Check for incremental bypass if baseline provided and incremental enabled
    bypass_scan = False
    if incremental and baseline_scan_id:
        baseline_scan = db.query(Scan).filter(Scan.id == baseline_scan_id).first()
        if baseline_scan:
            changed_files: Sequence[Union[str, Path]] = get_git_changed_files(source_path)
            crypto_affected = filter_crypto_affected_files(changed_files, source_path)
            # If zero files in the commit touched cryptographic surface, reuse previous findings
            if len(crypto_affected) == 0:
                bypass_scan = True
                for bf in baseline_scan.findings:
                    findings_data.append({
                        "fingerprint": bf.fingerprint,
                        "file_path": bf.file_path,
                        "line_start": bf.line_start,
                        "line_end": bf.line_end,
                        "code_snippet": bf.code_snippet,
                        "asset_type": bf.asset_type,
                        "algorithm": bf.algorithm,
                        "usage": bf.usage,
                        "library": bf.library,
                        "key_size": bf.key_size,
                        "severity": bf.severity,
                        "quantum_status": bf.quantum_status,
                        "hndl": bf.hndl,
                        "confidence": bf.confidence,
                        "rule_id": bf.rule_id,
                        "evidence": bf.evidence,
                    })
                total_count = baseline_scan.total_files
                scanned_count = baseline_scan.scanned_files
                score_report = {
                    "readiness_score": baseline_scan.readiness_score,
                    "coverage_percent": baseline_scan.coverage_percent,
                    "severity_counts": {
                        "critical": baseline_scan.critical_count,
                        "high": baseline_scan.high_count,
                        "medium": baseline_scan.medium_count,
                        "low": baseline_scan.low_count,
                        "quantum_safe": baseline_scan.quantum_safe_count
                    },
                    "hndl_count": baseline_scan.hndl_count,
                    "total_penalty": 0.0,
                    "incremental_bypass": True
                }

    if not bypass_scan:
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
            asset_type=f.get("asset_type", "source_code"),
            algorithm=f.get("algorithm", "Unknown"),
            usage=f.get("usage", "encryption"),
            library=f.get("library"),
            key_size=f.get("key_size"),
            severity=f.get("severity", "low"),
            quantum_status=f.get("quantum_status", "quantum_vulnerable"),
            hndl=bool(f.get("hndl", False)),
            confidence=float(f.get("confidence", 1.0)),
            rule_id=f.get("rule_id", "UNKNOWN"),
            evidence=f.get("evidence", ""),
            metadata_json={}
        )
        db.add(finding_obj)

    # 6. Update Scan Record
    raw_sev = score_report.get("severity_counts")
    sev_counts: Dict[str, Any] = raw_sev if isinstance(raw_sev, dict) else {}

    scan.status = "completed"
    scan.total_files = total_count
    scan.scanned_files = scanned_count
    scan.readiness_score = int(score_report.get("readiness_score", 0))
    scan.coverage_percent = float(score_report.get("coverage_percent", 0.0))
    scan.critical_count = int(sev_counts.get("critical", 0))
    scan.high_count = int(sev_counts.get("high", 0))
    scan.medium_count = int(sev_counts.get("medium", 0))
    scan.low_count = int(sev_counts.get("low", 0))
    scan.quantum_safe_count = int(sev_counts.get("quantum_safe", 0))
    scan.hndl_count = int(score_report.get("hndl_count", 0))
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

    try:
        scan.cache_stats = get_ast_cache().get_stats()
    except Exception:
        scan.cache_stats = {"hits": 0, "misses": 0, "total_requests": 0, "hit_ratio": 0.0, "bypass_ratio": 0.0}

    return scan
