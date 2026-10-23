from fastapi import APIRouter
from keynova.core.models import TlsInspectionRequest, TlsInspectionResponse
from keynova.services.tls.inspector import inspect_tls_endpoint

router = APIRouter()

@router.post("/inspect", response_model=TlsInspectionResponse)
def inspect_tls(payload: TlsInspectionRequest) -> TlsInspectionResponse:
    result = inspect_tls_endpoint(payload.host, payload.port)
    return TlsInspectionResponse(**result)
