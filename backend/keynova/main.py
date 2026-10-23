from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from keynova.core.database import init_db, DB_TYPE
from keynova.api.v1.projects import router as projects_router
from keynova.api.v1.scans import router as scans_router
from keynova.api.v1.graph import router as graph_router
from keynova.api.v1.export import router as export_router
from keynova.api.v1.tls import router as tls_router
from keynova.api.v1.playground import router as playground_router
from keynova.api.v1.remediation import router as remediation_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    init_db()
    print(f"🚀 Keynova Core Engine initialized. Database backend: {DB_TYPE}")
    yield

app = FastAPI(
    title="Keynova Post-Quantum Cryptographic Readiness API",
    description="Enterprise PQC Discovery, AST Analysis, and Verification Platform",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS for local development (Vite frontend on 5173/3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(projects_router, prefix="/api/v1/projects", tags=["Projects"])
app.include_router(scans_router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(graph_router, prefix="/api/v1/graph", tags=["Cryptographic Graph"])
app.include_router(export_router, prefix="/api/v1/export", tags=["Compliance Export"])
app.include_router(tls_router, prefix="/api/v1/tls", tags=["TLS Inspection"])
app.include_router(playground_router, prefix="/api/v1/playground", tags=["PQC Playground"])
app.include_router(remediation_router, prefix="/api/v1/findings", tags=["AI Remediation"])
app.include_router(remediation_router, prefix="/api/v1/remediation", tags=["AI Remediation"])
app.include_router(remediation_router, prefix="/api/v1", tags=["AI Remediation"])

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "Keynova PQC Engine",
        "database": DB_TYPE,
        "version": "1.0.0"
    }
