from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from keynova.core.database import init_db, DB_TYPE

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

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "Keynova PQC Engine",
        "database": DB_TYPE,
        "version": "1.0.0"
    }
