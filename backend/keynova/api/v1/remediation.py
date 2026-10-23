from fastapi import APIRouter, Depends, HTTPException
from typing import Optional, Any, List
from pydantic import BaseModel

try:
    from sqlalchemy.orm import Session
    from keynova.core.database import get_db, Finding  # type: ignore
except ImportError:
    Session = Any  # type: ignore
    get_db = None
    Finding = None

try:
    from keynova.core.models import RemediationResponse  # type: ignore
except ImportError:
    class RemediationResponse(BaseModel):
        finding_id: str
        provider: str
        algorithm: str
        target_standard: str
        explanation: str
        proposed_diff: str
        warnings: List[str]
        migration_effort: str

from keynova.services.remediation.engine import generate_remediation

router = APIRouter()

# ---------------------------------------------------------------------------
# Existing DB-lookup route (Akshant's scan findings via DB ID)
# ---------------------------------------------------------------------------
@router.post("/{finding_id}/suggest-fix", response_model=RemediationResponse)
def suggest_finding_fix(finding_id: str, db: Any = Depends(get_db) if get_db else None):
    if not db or not Finding:
        raise HTTPException(status_code=503, detail="Database service not initialized")
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding_dict = {
        "id": finding.id,
        "algorithm": finding.algorithm,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "code_snippet": finding.code_snippet,
        "usage": finding.usage,
        "severity": finding.severity
    }

    result = generate_remediation(finding_dict)
    return result


# ---------------------------------------------------------------------------
# /remediate alias — accepts a finding payload directly (no DB required).
# Used by the PQC Playground and frontend AI Remediation panel.
# ---------------------------------------------------------------------------
class RemediateRequest(BaseModel):
    id: Optional[str] = ""
    algorithm: str
    file_path: Optional[str] = "unknown"
    line_start: Optional[int] = 1
    code_snippet: Optional[str] = ""
    usage: Optional[str] = ""
    severity: Optional[str] = "medium"
    asset_type: Optional[str] = "source_code"
    library: Optional[str] = None


@router.post("/remediate", response_model=RemediationResponse)
def remediate_finding(payload: RemediateRequest):
    """
    Direct remediation endpoint — accepts a finding body and returns
    evidence-grounded PQC migration guidance without requiring a DB lookup.
    Alias for the AI Remediation Engine; complements /{finding_id}/suggest-fix.
    """
    finding_dict = payload.model_dump(exclude_none=False)
    result = generate_remediation(finding_dict)
    return result
