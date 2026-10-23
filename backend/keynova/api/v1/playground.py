from fastapi import APIRouter, HTTPException
from typing import Optional

try:
    from keynova.core.models import BenchmarkRequest, BenchmarkResponse  # type: ignore
except ImportError:
    from pydantic import BaseModel, Field

    class BenchmarkRequest(BaseModel):
        algorithm: str = Field(default="ML-KEM-768", description="Algorithm to benchmark (e.g. ML-KEM-768, ML-DSA-65, RSA-2048, ECDSA-P256)")
        iterations: int = Field(default=100, description="Benchmark iterations between 1 and 1000")

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

from keynova.services.crypto.playground import benchmark_algorithm

router = APIRouter()

@router.post("/benchmark", response_model=BenchmarkResponse)
def run_crypto_benchmark(payload: BenchmarkRequest):
    try:
        result = benchmark_algorithm(payload.algorithm, payload.iterations)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result
