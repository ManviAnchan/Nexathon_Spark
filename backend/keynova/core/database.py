import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import (
    create_engine, Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey, Index
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from keynova.core.config import POSTGRES_URL, FALLBACK_SQLITE_URL

# Try PostgreSQL first; fallback to SQLite if PostgreSQL fails to connect
try:
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True, pool_size=10, max_overflow=20)
    # Test connection
    with engine.connect() as conn:
        pass
    DB_TYPE = "postgresql"
    JSON_TYPE = JSONB
except Exception:
    engine = create_engine(FALLBACK_SQLITE_URL, connect_args={"check_same_thread": False})
    DB_TYPE = "sqlite"
    JSON_TYPE = JSON

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_uuid() -> str:
    return str(uuid.uuid4())

class Project(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    repository_url = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"

    id: Any = Column(String(36), primary_key=True, default=generate_uuid)
    project_id: Any = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    scan_number: Any = Column(Integer, default=1)
    status: Any = Column(String(32), default="pending")  # pending, analyzing, completed, failed
    scan_type: Any = Column(String(32), default="archive")  # archive, git, local
    archive_name: Any = Column(String(255), nullable=True)
    source_path: Any = Column(String(512), nullable=True)

    total_files: Any = Column(Integer, default=0)
    scanned_files: Any = Column(Integer, default=0)
    readiness_score: Any = Column(Integer, default=0)
    coverage_percent: Any = Column(Float, default=0.0)

    critical_count: Any = Column(Integer, default=0)
    high_count: Any = Column(Integer, default=0)
    medium_count: Any = Column(Integer, default=0)
    low_count: Any = Column(Integer, default=0)
    quantum_safe_count: Any = Column(Integer, default=0)
    hndl_count: Any = Column(Integer, default=0)

    created_at: Any = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at: Any = Column(DateTime(timezone=True), nullable=True)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

Index("idx_scans_project_created", Scan.project_id, Scan.created_at.desc())

class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    fingerprint = Column(String(64), nullable=False, index=True)  # SHA256(file_path:algorithm:usage)
    file_path = Column(String(512), nullable=False)
    line_start = Column(Integer, nullable=False)
    line_end = Column(Integer, nullable=False)
    code_snippet = Column(Text, nullable=False)
    asset_type = Column(String(64), default="source_code")  # source_code, manifest, certificate
    algorithm = Column(String(64), nullable=False)
    usage = Column(String(64), default="encryption")  # key_generation, signing, hashing, encryption
    library = Column(String(128), nullable=True)
    key_size = Column(Integer, nullable=True)
    severity = Column(String(32), nullable=False)  # critical, high, medium, low, quantum_safe
    quantum_status = Column(String(32), default="quantum_vulnerable")
    hndl = Column(Boolean, default=False)
    confidence = Column(Float, default=1.0)
    rule_id = Column(String(64), nullable=False)
    evidence = Column(Text, nullable=True)
    metadata_json = Column("metadata", JSON_TYPE, default=dict)

    scan = relationship("Scan", back_populates="findings")

Index("idx_findings_scan_severity", Finding.scan_id, Finding.severity)

class ScanComparison(Base):
    __tablename__ = "scan_comparisons"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    baseline_scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    target_scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    resolved_count = Column(Integer, default=0)
    added_count = Column(Integer, default=0)
    unchanged_count = Column(Integer, default=0)
    readiness_delta = Column(Integer, default=0)
    verification_status = Column(String(64), default="verified_clean")  # verified_clean, regression_detected, partial
    resolved_findings = Column(JSON_TYPE, default=list)
    added_findings = Column(JSON_TYPE, default=list)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    algorithm = Column(String(64), nullable=False)
    nist_standard = Column(String(64), nullable=False)
    iterations = Column(Integer, default=100)
    avg_keygen_latency_us = Column(Float, default=0.0)
    avg_encap_latency_us = Column(Float, default=0.0)
    avg_decap_latency_us = Column(Float, default=0.0)
    public_key_bytes = Column(Integer, default=0)
    ciphertext_bytes = Column(Integer, default=0)
    security_level = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Policy(Base):
    __tablename__ = "policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(128), default="Default Security Gate")
    min_readiness_score = Column(Integer, default=80)
    max_critical_findings = Column(Integer, default=0)
    max_high_findings = Column(Integer, default=2)
    block_on_hndl = Column(Boolean, default=True)

def init_db():
    Base.metadata.create_all(bind=engine)
