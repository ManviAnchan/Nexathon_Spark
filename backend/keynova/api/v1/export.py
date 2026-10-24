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
from keynova.services.exporters.cbom import generate_cyclonedx_cbom, serialize_cbom_json
from keynova.services.exporters.sarif import generate_sarif_report

try:
    from keynova.services.exporters.pdf import generate_pdf_report
except Exception:
    generate_pdf_report = None

router = APIRouter()

DEMO_FINDINGS = [
    {"id": "demo-rsa", "fingerprint": "demo-fp-rsa-2048", "rule_id": "PYTHON_RSA_KEYGEN", "confidence": 1.0, "file_path": "backend/crypto_service.py", "line_start": 24, "line_end": 24, "algorithm": "RSA-2048", "usage": "key_generation", "library": "cryptography", "key_size": 2048, "severity": "critical", "quantum_status": "quantum_vulnerable", "hndl": True, "evidence": "RSA key establishment is vulnerable to Shor's algorithm.", "asset_type": "source_code", "code_snippet": "rsa.generate_private_key(public_exponent=65537, key_size=2048)"},
    {"id": "demo-ecc", "fingerprint": "demo-fp-ecc-secp256r1", "rule_id": "PYTHON_ECC_KEYGEN", "confidence": 0.95, "file_path": "backend/auth.py", "line_start": 41, "line_end": 41, "algorithm": "ECC-SECP256R1", "usage": "token_signing", "library": "cryptography", "key_size": 256, "severity": "high", "quantum_status": "quantum_vulnerable", "hndl": True, "evidence": "Elliptic curve signatures are breakable on quantum hardware.", "asset_type": "source_code", "code_snippet": "ec.generate_private_key(ec.SECP256R1())"},
    {"id": "demo-md5", "fingerprint": "demo-fp-md5", "rule_id": "PYTHON_MD5_HASH", "confidence": 1.0, "file_path": "backend/hasher.py", "line_start": 17, "line_end": 17, "algorithm": "MD5", "usage": "password_hashing", "library": "hashlib", "key_size": 128, "severity": "medium", "quantum_status": "classical_weakness", "hndl": False, "evidence": "MD5 suffers from collision vulnerabilities.", "asset_type": "source_code", "code_snippet": "hashlib.md5(password.encode()).hexdigest()"},
    {"id": "demo-dependency", "fingerprint": "demo-fp-pycryptodome", "rule_id": "DEP_LEGACY_CRYPTO", "confidence": 0.9, "file_path": "requirements.txt", "line_start": 3, "line_end": 3, "algorithm": "Legacy crypto dependency", "usage": "dependency", "library": "pycryptodome", "key_size": 0, "severity": "low", "quantum_status": "quantum_vulnerable", "hndl": False, "evidence": "PyCryptodome legacy dependency.", "asset_type": "manifest", "code_snippet": "pycryptodome==3.10.1"}
]

@router.get("/{scan_id}/cbom")
def export_cbom(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        if scan_id.startswith("demo-"):
            cbom = generate_cyclonedx_cbom(
                project_name="Keynova Demo Workspace",
                scan_id=scan_id,
                findings=DEMO_FINDINGS,
                readiness_score=48
            )
            cbom_json = serialize_cbom_json(cbom, indent=2)
            return Response(
                content=cbom_json,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=Keynova_CBOM_{scan_id[:8]}.json"}
            )
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

    cbom_json = serialize_cbom_json(cbom, indent=2)
    return Response(
        content=cbom_json,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=Keynova_CBOM_{scan_id[:8]}.json"}
    )

@router.get("/{scan_id}/pdf")
def export_pdf(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        if scan_id.startswith("demo-") and generate_pdf_report:
            demo_meta = {
                "id": scan_id,
                "readiness_score": 48,
                "coverage_percent": 100.0,
                "scanned_files": 4,
                "total_files": 4,
                "hndl_count": 2
            }
            pdf_bytes = generate_pdf_report("Keynova Demo Workspace", demo_meta, DEMO_FINDINGS)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=Keynova_Security_Report_{scan_id[:8]}.pdf"}
            )
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

@router.get("/{scan_id}/sarif")
def export_sarif(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        if scan_id.startswith("demo-"):
            sarif = generate_sarif_report(
                findings=DEMO_FINDINGS,
                project_name="Keynova Demo Workspace",
                scan_id=scan_id
            )
            return JSONResponse(
                content=sarif,
                headers={"Content-Disposition": f"attachment; filename=Keynova_SARIF_{scan_id[:8]}.sarif"}
            )
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [
        {
            "id": f.id,
            "rule_id": getattr(f, "rule_id", "UNKNOWN"),
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
    sarif = generate_sarif_report(
        findings=findings,
        project_name=project_name,
        scan_id=scan.id
    )

    return JSONResponse(
        content=sarif,
        headers={"Content-Disposition": f"attachment; filename=Keynova_SARIF_{scan_id[:8]}.sarif"}
    )


