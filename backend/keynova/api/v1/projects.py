import shutil
import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from keynova.core.database import get_db, Project, Scan
from keynova.core.models import ProjectCreate, ProjectResponse, ScanStatusResponse
from keynova.core.config import UPLOAD_DIR, EXTRACTED_DIR
from keynova.services.ingestion.zip import safe_extract_zip, ZipSlipSecurityError, DecompressionBombError
from keynova.services.scanner.orchestrator import execute_scan

router = APIRouter()

@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    proj = Project(name=payload.name, repository_url=payload.repository_url)
    db.add(proj)
    db.commit()
    db.refresh(proj)
    return proj

@router.get("", response_model=List[ProjectResponse])
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).order_by(Project.created_at.desc()).all()

@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@router.delete("/{project_id}")
def delete_project(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()
    return {"status": "deleted", "project_id": project_id}

@router.get("/{project_id}/scans", response_model=List[ScanStatusResponse])
def list_project_scans(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    scans = db.query(Scan).filter(Scan.project_id == project_id).order_by(Scan.created_at.desc()).all()
    results = []
    for s in scans:
        results.append({
            "id": s.id,
            "project_id": s.project_id,
            "status": s.status,
            "scan_type": s.scan_type,
            "archive_name": s.archive_name,
            "total_files": s.total_files,
            "scanned_files": s.scanned_files,
            "coverage_percent": s.coverage_percent,
            "readiness_score": s.readiness_score,
            "severity_counts": {
                "critical": s.critical_count,
                "high": s.high_count,
                "medium": s.medium_count,
                "low": s.low_count,
                "quantum_safe": s.quantum_safe_count
            },
            "hndl_count": s.hndl_count,
            "created_at": s.created_at,
            "completed_at": s.completed_at,
            "cache_stats": getattr(s, "cache_stats", None)
        })
    return results

@router.post("/{project_id}/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_project_archive(
    project_id: str,
    file: UploadFile = File(...),
    baseline_scan_id: str = None,
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archives are supported")

    # Save uploaded file
    target_zip = UPLOAD_DIR / f"{project_id}_{file.filename}"
    with open(target_zip, "wb") as f_out:
        shutil.copyfileobj(file.file, f_out)

    extract_folder = EXTRACTED_DIR / f"{project_id}_{file.filename}_extracted"
    
    try:
        extracted_files = safe_extract_zip(target_zip, extract_folder)
    except ZipSlipSecurityError as e:
        raise HTTPException(status_code=400, detail=f"Security Violation: {e}")
    except DecompressionBombError as e:
        raise HTTPException(status_code=400, detail=f"Decompression Bomb: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to extract archive: {e}")

    # Create scan record and automatically trigger analysis
    scan_count = db.query(Scan).filter(Scan.project_id == project_id).count()
    new_scan = Scan(
        project_id=project_id,
        scan_number=scan_count + 1,
        status="pending",
        scan_type="archive",
        archive_name=file.filename,
        source_path=str(extract_folder)
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Execute synchronous scan
    executed = execute_scan(
        db=db,
        scan_id=new_scan.id,
        source_path=extract_folder,
        baseline_scan_id=baseline_scan_id
    )

    return {
        "project_id": project_id,
        "scan_id": executed.id,
        "archive_name": file.filename,
        "extracted_files": extracted_files,
        "readiness_score": executed.readiness_score,
        "status": executed.status
    }

class GitCloneRequest(BaseModel):
    repository_url: str
    branch: Optional[str] = None
    baseline_scan_id: Optional[str] = None

@router.post("/{project_id}/git-clone", status_code=status.HTTP_202_ACCEPTED)
def clone_and_scan_repository(
    project_id: str,
    payload: GitCloneRequest,
    db: Session = Depends(get_db)
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    from keynova.services.ingestion.git import clone_git_repository, GitSecurityViolation, GitCloneError

    repo_dir = EXTRACTED_DIR / f"{project_id}_git_{uuid.uuid4().hex[:8]}"
    try:
        clone_git_repository(payload.repository_url, repo_dir, payload.branch)
    except GitSecurityViolation as e:
        raise HTTPException(status_code=400, detail=str(e))
    except GitCloneError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected clone error: {e}")

    scan_count = db.query(Scan).filter(Scan.project_id == project_id).count()
    repo_name = payload.repository_url.split("/")[-1].replace(".git", "")
    new_scan = Scan(
        project_id=project_id,
        scan_number=scan_count + 1,
        status="pending",
        scan_type="git",
        archive_name=repo_name,
        source_path=str(repo_dir)
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    executed = execute_scan(
        db=db,
        scan_id=new_scan.id,
        source_path=repo_dir,
        baseline_scan_id=payload.baseline_scan_id
    )

    return {
        "project_id": project_id,
        "scan_id": executed.id,
        "archive_name": repo_name,
        "total_files": executed.total_files,
        "readiness_score": executed.readiness_score,
        "status": executed.status
    }
