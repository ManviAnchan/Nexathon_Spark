from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any

from keynova.core.database import get_db, Scan, Finding, ScanComparison
from keynova.core.models import ScanStatusResponse, FindingsListResponse, FindingResponse, ScanComparisonResponse

router = APIRouter()

from datetime import datetime, timezone

DEMO_SCAN_DATA = {
    "id": "demo-scan",
    "project_id": "demo-payment-suite",
    "status": "completed",
    "scan_type": "archive",
    "archive_name": "Keynova Demo Workspace",
    "total_files": 12,
    "scanned_files": 12,
    "coverage_percent": 100.0,
    "readiness_score": 48,
    "severity_counts": {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
        "quantum_safe": 0
    },
    "hndl_count": 2,
    "created_at": datetime.now(timezone.utc),
    "completed_at": datetime.now(timezone.utc),
    "cache_stats": {
        "hits": 28,
        "misses": 4,
        "total_requests": 32,
        "hit_ratio": 0.875,
        "bypass_ratio": 0.125
    }
}

@router.get("/cache/stats")
def get_cache_statistics():
    from keynova.services.cache.ast_cache import get_ast_cache
    return get_ast_cache().get_stats()

@router.get("/project/{project_id}", response_model=List[ScanStatusResponse])
def get_scans_by_project(project_id: str, db: Session = Depends(get_db)):
    from keynova.api.v1.projects import list_project_scans
    return list_project_scans(project_id, db)

@router.get("/compare/{baseline_id}/{target_id}", response_model=ScanComparisonResponse)
def compare_two_scans(baseline_id: str, target_id: str, db: Session = Depends(get_db)):
    return get_scan_diff(scan_id=target_id, baseline_id=baseline_id, db=db)

@router.get("/{scan_id}", response_model=ScanStatusResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        if scan_id.startswith("demo-") or scan_id.startswith("sample-"):
            res = dict(DEMO_SCAN_DATA)
            res["id"] = scan_id
            return res
        raise HTTPException(status_code=404, detail="Scan not found")

    from keynova.services.cache.ast_cache import get_ast_cache
    live_stats = get_ast_cache().get_stats()

    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status,
        "scan_type": scan.scan_type,
        "archive_name": scan.archive_name,
        "total_files": scan.total_files,
        "scanned_files": scan.scanned_files,
        "coverage_percent": scan.coverage_percent,
        "readiness_score": scan.readiness_score,
        "severity_counts": {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "quantum_safe": scan.quantum_safe_count
        },
        "hndl_count": scan.hndl_count,
        "created_at": scan.created_at,
        "completed_at": scan.completed_at,
        "cache_stats": getattr(scan, "cache_stats", None) or live_stats
    }

@router.get("/{scan_id}/findings", response_model=FindingsListResponse)
def list_findings(
    scan_id: str,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        if scan_id.startswith("demo-") or scan_id.startswith("sample-"):
            from keynova.api.v1.export import DEMO_FINDINGS
            items = []
            for df in DEMO_FINDINGS:
                if severity and str(df.get("severity") or "").lower() != severity.lower():
                    continue
                item_dict = dict(df)
                item_dict["scan_id"] = scan_id
                items.append(item_dict)
            return {
                "scan_id": scan_id,
                "total": len(items),
                "items": items[:limit]
            }
        raise HTTPException(status_code=404, detail="Scan not found")

    query = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        query = query.filter(Finding.severity == severity.lower())

    total = query.count()
    items = query.limit(limit).all()

    return {
        "scan_id": scan_id,
        "total": total,
        "items": items
    }

@router.get("/{scan_id}/diff/{baseline_id}", response_model=ScanComparisonResponse)
def get_scan_diff(scan_id: str, baseline_id: str, db: Session = Depends(get_db)):
    comp = db.query(ScanComparison).filter(
        ScanComparison.baseline_scan_id == baseline_id,
        ScanComparison.target_scan_id == scan_id
    ).first()

    if not comp:
        base = db.query(Scan).filter(Scan.id == baseline_id).first()
        targ = db.query(Scan).filter(Scan.id == scan_id).first()
        if not base or not targ:
            raise HTTPException(status_code=404, detail="Scans not found for comparison")

        base_findings = [
            {"fingerprint": f.fingerprint, "file_path": f.file_path, "algorithm": f.algorithm, "usage": f.usage, "severity": f.severity}
            for f in base.findings
        ]
        targ_findings = [
            {"fingerprint": f.fingerprint, "file_path": f.file_path, "algorithm": f.algorithm, "usage": f.usage, "severity": f.severity}
            for f in targ.findings
        ]
        try:
            from keynova.services.intelligence.diff import compare_scans
        except ImportError:
            from keynova.services.scanner.orchestrator import compare_scans
        res = compare_scans(base_findings, targ_findings, base.readiness_score, targ.readiness_score)
        comp = ScanComparison(
            baseline_scan_id=base.id,
            target_scan_id=targ.id,
            resolved_count=res["resolved_count"],
            added_count=res["added_count"],
            unchanged_count=res["unchanged_count"],
            readiness_delta=res["readiness_delta"],
            verification_status=res["verification_status"],
            resolved_findings=res["resolved_findings"],
            added_findings=res["added_findings"]
        )
        db.add(comp)
        db.commit()
        db.refresh(comp)

    return comp

@router.get("/{scan_id}/export/cbom")
def get_scan_cbom_export(scan_id: str, db: Session = Depends(get_db)):
    try:
        from keynova.api.v1.export import export_cbom
        return export_cbom(scan_id, db)
    except ImportError:
        raise HTTPException(status_code=501, detail="CBOM exporter route not loaded")

@router.get("/{scan_id}/export/pdf")
def get_scan_pdf_export(scan_id: str, db: Session = Depends(get_db)):
    try:
        from keynova.api.v1.export import export_pdf
        return export_pdf(scan_id, db)
    except ImportError:
        raise HTTPException(status_code=501, detail="PDF exporter route not loaded")
