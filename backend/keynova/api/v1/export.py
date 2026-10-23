import sys
from pathlib import Path

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from keynova.core.database import get_db, Scan
from keynova.services.exporters.cbom import generate_cyclonedx_cbom

try:
    from keynova.services.exporters.pdf import generate_pdf_report
except Exception:
    generate_pdf_report = None

router = APIRouter()

@router.get("/{scan_id}/cbom")
def export_cbom(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [
        {
            "id": f.id,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "algorithm": f.algorithm,
            "usage": f.usage,
            "key_size": f.key_size,
            "severity": f.severity,
            "quantum_status": f.quantum_status,
            "hndl": f.hndl,
            "evidence": f.evidence,
            "asset_type": getattr(f, "asset_type", "source_code"),
            "library": getattr(f, "library", None),
            "code_snippet": getattr(f, "code_snippet", ""),
        }
        for f in scan.findings
    ]

    project_name = scan.project.name if (scan.project and getattr(scan.project, "name", None)) else "Cryptographic Service"
    cbom = generate_cyclonedx_cbom(
        project_name=project_name,
        scan_id=scan.id,
        findings=findings,
        readiness_score=scan.readiness_score if scan.readiness_score is not None else 0
    )

    return JSONResponse(
        content=cbom,
        headers={"Content-Disposition": f"attachment; filename=Keynova_CBOM_{scan_id[:8]}.json"}
    )

@router.get("/{scan_id}/pdf")
def export_pdf(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if generate_pdf_report is None:
        raise HTTPException(
            status_code=501,
            detail="PDF generation is currently unavailable (reportlab is not installed)"
        )

    findings = [
        {
            "id": f.id,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "algorithm": f.algorithm,
            "usage": f.usage,
            "key_size": f.key_size,
            "severity": f.severity,
            "hndl": f.hndl
        }
        for f in scan.findings
    ]

    scan_meta = {
        "id": scan.id,
        "readiness_score": scan.readiness_score,
        "coverage_percent": scan.coverage_percent,
        "scanned_files": scan.scanned_files,
        "total_files": scan.total_files,
        "hndl_count": scan.hndl_count
    }

    project_name = scan.project.name if (scan.project and getattr(scan.project, "name", None)) else "Payment Gateway"
    try:
        pdf_bytes = generate_pdf_report(project_name, scan_meta, findings)
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=Keynova_Security_Report_{scan_id[:8]}.pdf"}
    )

