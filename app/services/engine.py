import json
import logging
import asyncio
import uuid
from pathlib import Path
from datetime import datetime
from typing import List, Tuple

from app.core.config import settings
from app.api.models import (
    ScanRequest, ScanResponse, TargetInfo, TrivyInfo, 
    ScanCounts, VulnCounts, Decision, Recommendation, 
    TimingInfo, Severity
)
from app.services.scanner import run_trivy_scan
from app.services.hasher import calculate_sha256

logger = logging.getLogger(__name__)

class ScanEngine:
    def _validate_path(self, path_str: str) -> Path:
        """
        Validates that the path is safe, exists, is a file, and is within allowed roots.
        Returns the resolved Path object.
        """
        try:
            path = Path(path_str).resolve()
        except Exception as e:
            raise ValueError(f"Invalid path: {e}")

        if not path.exists():
            raise ValueError("File does not exist")
        
        if not path.is_file():
            raise ValueError("Path is not a regular file")
            
        if path.is_symlink():
            raise ValueError("Symlinks are not allowed")

        allowed = False
        for root in settings.allowed_roots_list:
            # Check if path is within root
            try:
                # relative_to checks if path is subpath of root
                path.relative_to(Path(root).resolve())
                allowed = True
                break
            except ValueError:
                continue
        
        if not allowed:
            raise ValueError(f"Path is not within allowed scan roots: {settings.allowed_roots_list}")
            
        return path

    def _parse_trivy_results(self, json_path: Path) -> Tuple[ScanCounts, int]:
        """
        Parses the raw Trivy JSON output to count vulnerabilities, secrets, etc.
        Returns ScanCounts and the total exit code context (simulated).
        """
        counts = ScanCounts()
        
        if not json_path.exists():
            logger.warning(f"Trivy output file not found: {json_path}")
            return counts, 0

        try:
            with open(json_path, "r") as f:
                data = json.load(f)
                
            # Trivy JSON format usually has a "Results" list
            results = data.get("Results", [])
            
            for res in results:
                target = res.get("Target", "")
                
                # Vulnerabilities
                vulns = res.get("Vulnerabilities", [])
                for v in vulns:
                    severity = v.get("Severity", "UNKNOWN")
                    # Increment specific severity
                    if severity == "CRITICAL":
                        counts.vulnerabilities.CRITICAL += 1
                    elif severity == "HIGH":
                        counts.vulnerabilities.HIGH += 1
                    elif severity == "MEDIUM":
                        counts.vulnerabilities.MEDIUM += 1
                    elif severity == "LOW":
                        counts.vulnerabilities.LOW += 1
                    else:
                        counts.vulnerabilities.UNKNOWN += 1
                
                # Secrets
                # Secrets usually appear as Class: "secret" or Type: "secret" depending on scanner
                # In standard trivy: "Secrets": [...] or "Vulnerabilities" [...]
                # For `trivy fs`, secrets are often in a separate or same Result block with Class/Type.
                # Let's count "Secrets" list if present
                secrets = res.get("Secrets", [])
                counts.secrets += len(secrets)
                
                # Licenses - often in "Licenses" list if license scanner used
                licenses = res.get("Licenses", [])
                # Or sometimes "Vulnerabilities" with Class="License"? 
                # Trivy License scanning usually puts them in "Licenses" key in modern versions 
                # or checks for Severity="HIGH"/"CRITICAL" on license issues.
                # Assuming distinct list or counting via some other marker if needed.
                # For this PoC, we count the "Licenses" array entries.
                counts.licenses += len(licenses)

        except Exception as e:
            logger.error(f"Failed to parse Trivy JSON: {e}")
            
        return counts, 0

    def _make_decision(self, counts: ScanCounts) -> Decision:
        reasons = []
        rec = Recommendation.ALLOW
        
        # BLOCK logic
        if counts.vulnerabilities.CRITICAL > 0:
            rec = Recommendation.BLOCK
            reasons.append(f"Found {counts.vulnerabilities.CRITICAL} CRITICAL vulnerabilities")
            
        if counts.secrets > 0:
            rec = Recommendation.BLOCK
            reasons.append(f"Found {counts.secrets} secrets")
            
        # If already BLOCK, we can just return or add more reasons. 
        # But if not BLOCK, check REVIEW.
        if rec != Recommendation.BLOCK:
            if counts.vulnerabilities.HIGH > 0:
                rec = Recommendation.REVIEW
                reasons.append(f"Found {counts.vulnerabilities.HIGH} HIGH vulnerabilities")
            
            if counts.licenses > 0:
                # If we consider any license finding as REVIEW? 
                # SPEC says: licenses > 0 -> REVIEW
                rec = Recommendation.REVIEW
                reasons.append(f"Found {counts.licenses} license issues")
        
        if rec == Recommendation.ALLOW:
            reasons.append("No blocking or review-required findings detected")
            
        return Decision(recommendation=rec, reasons=reasons)

    async def process_scan(self, request: ScanRequest) -> ScanResponse:
        start_time = datetime.utcnow()
        scan_id = uuid.uuid4()
        
        # 1. Validation
        target_path = self._validate_path(request.path)
        
        # 2. Hashing (Compute while trivy runs? No, simple sequential for PoC safety)
        # Using a thread/process pool for CPU bound work like hashing if file is huge
        # For PoC, synchronous call wrapped in to_thread is fine
        sha256 = await asyncio.to_thread(calculate_sha256, target_path)
        file_size = target_path.stat().st_size
        
        # 3. Directories setup
        raw_out_dir = Path(settings.RAW_OUTPUT_DIR) / "trivy"
        raw_out_dir.mkdir(parents=True, exist_ok=True)
        trivy_out_path = raw_out_dir / f"{scan_id}.json"
        
        # 4. Run Trivy
        # Note: process_scan is async, but run_trivy_scan is sync (subprocess.run).
        # We wrap it.
        exit_code = await asyncio.to_thread(
            run_trivy_scan,
            target_path=target_path,
            output_path=trivy_out_path,
            scanners=request.scanners,
            severities=request.severity,
            ignore_unfixed=request.ignore_unfixed,
            timeout_seconds=request.timeout_seconds
        )
        
        # 5. Parse Results
        counts, _ = await asyncio.to_thread(self._parse_trivy_results, trivy_out_path)
        
        # 6. Make Decision
        decision = self._make_decision(counts)
        
        # 7. Construct Response
        finish_time = datetime.utcnow()
        duration_ms = int((finish_time - start_time).total_seconds() * 1000)
        
        # Get Trivy Version (could cache this)
        trivy_version = await asyncio.to_thread(lambda: "0.1.0") # Placeholder or call get_trivy_version
        
        # Use scanner.get_trivy_version actually
        from app.services.scanner import get_trivy_version
        trivy_version = await asyncio.to_thread(get_trivy_version)

        return ScanResponse(
            scan_id=scan_id,
            target=TargetInfo(
                path=str(target_path),
                sha256=sha256,
                size_bytes=file_size
            ),
            trivy=TrivyInfo(
                version=trivy_version,
                exit_code=exit_code,
                raw_json_path=str(trivy_out_path)
            ),
            counts=counts,
            decision=decision,
            timing=TimingInfo(
                started_at=start_time,
                finished_at=finish_time,
                duration_ms=duration_ms
            )
        )

scan_engine = ScanEngine()
