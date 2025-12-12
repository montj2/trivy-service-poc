from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    ALLOWED_SCAN_ROOTS: str = "/mnt/artifacts"
    RAW_OUTPUT_DIR: str = "/mnt/out"
    TRIVY_CACHE_DIR: str = "/var/lib/trivy"
    MAX_CONCURRENT_SCANS: int = 2
    TRIVY_BINARY_PATH: str = "trivy"
    
    @property
    def allowed_roots_list(self) -> List[str]:
        return [p.strip() for p in self.ALLOWED_SCAN_ROOTS.split(",") if p.strip()]

settings = Settings()
