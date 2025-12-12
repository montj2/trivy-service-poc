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
        Prevents symlink traversal by rejecting any path component that is a symlink.
        Returns the resolved Path object.
        """
        try:
            # 1. Basic sanity check
            raw_path = Path(path_str)
            if not raw_path.is_absolute():
                 # For security, we might enforce absolute paths or resolve strictly from a known cwd, 
                 # but usually inputs should be absolute or we treat them relative to cwd found via resolve later.
                 # Let's check existence first on the raw path to ensure we can inspect components.
                 pass

            # 2. Strict Symlink Check on all components
            # We must check the path itself and all its parents.
            # Note: exists() return False for broken symlinks, but is_symlink() is True.
            # We want to catch ANY symlink in the chain.
            
            # Check the file itself
            if raw_path.is_symlink():
                raise ValueError(f"Symlinks are not allowed: {raw_path.name}")
            
            # Check all parents
            for parent in raw_path.parents:
                if parent.is_symlink():
                    raise ValueError(f"Path traversal via symlink not allowed: {parent}")

            # 3. Resolve and Check Existence
            # Now safe to resolve since we checked the input path's lineage (at least as provided).
            # Note: A race condition is possible (TOCTOU), but for this PoC/Procurement gate, 
            # this check is the standard mitigation pattern requested.
            resolved_path = raw_path.resolve()

            if not resolved_path.exists():
                raise ValueError("File does not exist")

            if not resolved_path.is_file():
                raise ValueError("Path is not a regular file")

            # 4. Check Allowed Roots
            allowed = False
            for root in settings.allowed_roots_list:
                root_path = Path(root).resolve()
                try:
                    resolved_path.relative_to(root_path)
                    allowed = True
                    break
                except ValueError:
                    continue
            
            if not allowed:
                 raise ValueError(f"Path is not within allowed scan roots: {settings.allowed_roots_list}")

            return resolved_path

        except Exception as e:
            # Re-raise known ValueErrors, wrap others
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"Invalid path validation: {e}")

    def _parse_trivy_results(self, json_path: Path) -> Tuple[ScanCounts, int]:
        """
        Parses the raw Trivy JSON output to count vulnerabilities, secrets, etc.
        Returns ScanCounts and the total exit code context (simulated).
        Resilient parsing: iterates all result blocks, handling missing keys safely.
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
            
            # If Results is None (can happen in empty scans), ensure it's iterable
            if results is None:
                results = []
            
            for res in results:
                # 1. Vulnerabilities
                vulns = res.get("Vulnerabilities", [])
                if vulns:
                    for v in vulns:
                        severity = v.get("Severity", "UNKNOWN")
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
                
                # 2. Secrets
                # Secrets might be in "Secrets" key OR "Vulnerabilities" with specific Class, 
                # but "Secrets" key is standard for 'trivy fs --scanners secret'
                secrets = res.get("Secrets", [])
                if secrets:
                    counts.secrets += len(secrets)
                
                # 3. Licenses
                licenses = res.get("Licenses", [])
                if licenses:
                    counts.licenses += len(licenses)

                # 4. Misconfigurations (Future proofing, even if not strictly used in current decision logic)
                misconfigs = res.get("Misconfigurations", [])
                if misconfigs:
                    # We don't have a count bucket for this in the current model, 
                    # but we safely parse it without error.
                    pass

        except json.JSONDecodeError:
             logger.error(f"Invalid JSON in Trivy output: {json_path}")
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
