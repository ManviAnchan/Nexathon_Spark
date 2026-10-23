from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from keynova.core.database import get_db, Scan
from keynova.core.models import GraphResponse
from keynova.services.intelligence.graph import build_dependency_graph

router = APIRouter()

@router.get("/{scan_id}", response_model=GraphResponse)
def get_crypto_graph(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [
        {
            "id": f.id,
            "file_path": f.file_path,
            "library": f.library,
            "algorithm": f.algorithm,
            "severity": f.severity,
            "hndl": f.hndl,
            "usage": f.usage
        }
        for f in scan.findings
    ]

    project_name = scan.project.name if scan.project else "Cryptographic Service"
    graph_data = build_dependency_graph(project_name, findings)

    return {
        "scan_id": scan.id,
        "nodes": graph_data["nodes"],
        "edges": graph_data["edges"]
    }
