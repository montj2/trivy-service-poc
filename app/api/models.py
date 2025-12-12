from pydantic import BaseModel, Field, UUID4, validator
from typing import List, Optional
from enum import Enum
from datetime import datetime

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class ScannerType(str, Enum):
    VULN = "vuln"
    SECRET = "secret"
    LICENSE = "license"
    MISCONF = "misconfig"

class Recommendation(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"

class ScanRequest(BaseModel):
    path: str
    severity: List[Severity] = Field(default_factory=lambda: [Severity.HIGH, Severity.CRITICAL])
    scanners: List[ScannerType] = Field(default_factory=lambda: [ScannerType.VULN, ScannerType.SECRET])
    timeout_seconds: int = 120
    ignore_unfixed: bool = False

class TargetInfo(BaseModel):
    path: str
    sha256: str
    size_bytes: int

class TrivyInfo(BaseModel):
    version: str
    exit_code: int
    raw_json_path: str

class VulnCounts(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    UNKNOWN: int = 0

class ScanCounts(BaseModel):
    vulnerabilities: VulnCounts = Field(default_factory=VulnCounts)
    secrets: int = 0
    licenses: int = 0

class Decision(BaseModel):
    recommendation: Recommendation
    reasons: List[str]

class TimingInfo(BaseModel):
    started_at: datetime
    finished_at: datetime
    duration_ms: int

class ScanResponse(BaseModel):
    scan_id: UUID4
    target: TargetInfo
    trivy: TrivyInfo
    counts: ScanCounts
    decision: Decision
    timing: TimingInfo
