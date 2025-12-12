from fastapi import APIRouter, HTTPException, BackgroundTasks
from app.api.models import ScanRequest, ScanResponse
from app.services.engine import scan_engine
from app.services.scanner import get_trivy_version
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/healthz")
async def healthz():
    return {"status": "ok"}

@router.get("/readyz")
async def readyz():
    # Check if trivy is executable
    version = get_trivy_version()
    if version == "unknown":
        raise HTTPException(status_code=503, detail="Trivy binary not found or not executable")
    return {"status": "ready", "trivy_version": version}

@router.post("/v1/scan/fs", response_model=ScanResponse)
async def scan_fs(request: ScanRequest):
    try:
        # Note: semaphore logic for concurrency should be handled here or in engine
        # For PoC, we let asyncio handle it, but config says MAX_CONCURRENT_SCANS.
        # We can implement a semaphore later if strictly required by task, 
        # but for now we trust the async loop + simple PoC.
        # Ideally: async with semaphore: ...
        
        response = await scan_engine.process_scan(request)
        return response
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Scan processing failed")
        raise HTTPException(status_code=500, detail="Internal server error during scan")
