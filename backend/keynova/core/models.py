from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

class ProjectCreate(BaseModel):
    name: str
    repository_url: Optional[str] = None

class ProjectResponse(BaseModel):
    id: str
    name: str
    repository_url: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ScanDispatch(BaseModel):
    scan_type: str = "archive"  # archive, git, local_test
    git_branch: Optional[str] = "main"
    baseline_scan_id: Optional[str] = None

class ScanStatusResponse(BaseModel):
    id: str
    project_id: str
    status: str
    scan_type: str
    archive_name: Optional[str] = None
    total_files: int
    scanned_files: int
    coverage_percent: float
    readiness_score: int
    severity_counts: Dict[str, int]
    hndl_count: int
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class FindingResponse(BaseModel):
    id: str
    scan_id: str
    fingerprint: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    asset_type: str
    algorithm: str
    usage: str
    library: Optional[str] = None
    key_size: Optional[int] = None
    severity: str
    quantum_status: str
    hndl: bool
    confidence: float
    rule_id: str
    evidence: Optional[str] = None
    metadata_json: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)

class FindingsListResponse(BaseModel):
    scan_id: str
    total: int
    items: List[FindingResponse]

class RemediationResponse(BaseModel):
    finding_id: str
    provider: str
    algorithm: str
    target_standard: str
    explanation: str
    proposed_diff: str
    warnings: List[str]
    migration_effort: str

class ScanComparisonResponse(BaseModel):
    id: str
    baseline_scan_id: str
    target_scan_id: str
    readiness_delta: int
    resolved_count: int
    added_count: int
    unchanged_count: int
    resolved_findings: List[Dict[str, Any]]
    added_findings: List[Dict[str, Any]]
    verification_status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GraphNode(BaseModel):
    id: str
    type: str  # application, file, library, algorithm
    data: Dict[str, Any]
    position: Dict[str, float]

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    animated: Optional[bool] = False
    style: Optional[Dict[str, Any]] = None

class GraphResponse(BaseModel):
    scan_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]

class BenchmarkRequest(BaseModel):
    algorithm: str = "ML-KEM-768"  # ML-KEM-768, ML-DSA-65, RSA-2048, ECDSA-P256
    iterations: int = 100

class BenchmarkResponse(BaseModel):
    algorithm: str
    nist_standard: str
    iterations: int
    avg_keygen_latency_us: float
    avg_encap_latency_us: float
    avg_decap_latency_us: float
    public_key_bytes: int
    ciphertext_bytes: int
    security_level: int

class TlsInspectionRequest(BaseModel):
    host: str
    port: int = 443

class TlsInspectionResponse(BaseModel):
    host: str
    port: int
    resolved_ip: str
    is_safe: bool
    tls_version: str
    cipher_suite: str
    certificate_subject: str
    certificate_issuer: str
    key_size: int
    quantum_safe: bool
    error: Optional[str] = None
