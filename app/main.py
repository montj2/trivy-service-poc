import logging
import asyncio
from fastapi import FastAPI
from app.api.routes import router
from app.core.config import settings

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

description = """
Trivy FS Scan API is a containerized service for scanning local files using `trivy fs`.

## Features
* **File Scanning**: Scans single binary files for vulnerabilities, secrets, and configuration issues.
* **Policy Engine**: logical decision making (BLOCK/REVIEW/ALLOW) based on scan results.
* **Persistence**: Saves raw Trivy JSON reports for audit trails.
"""

app = FastAPI(
    title="Trivy FS Scan API",
    description=description,
    version="0.1.0",
    contact={
        "name": "Security Engineering",
        "email": "seceng@example.com",
    },
    docs_url="/docs",
    redoc_url="/redoc"
)

app.include_router(router)

# Concurrency limiting (Simple Semaphore)
scan_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_SCANS)

@app.middleware("http")
async def limit_concurrency(request, call_next):
    if request.url.path == "/v1/scan/fs" and request.method == "POST":
        try:
            async with scan_semaphore:
                response = await call_next(request)
                return response
        except Exception as e:
            # If semaphore acquire fails or times out (if we added timeout)
            raise e
    else:
        return await call_next(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
