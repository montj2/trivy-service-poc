import subprocess
import json
import logging
import asyncio
from typing import List, Optional, Dict, Any
from pathlib import Path
from app.core.config import settings
from app.api.models import ScannerType, Severity

logger = logging.getLogger(__name__)

class TrivyScanError(Exception):
    pass

def get_trivy_version() -> str:
    try:
        result = subprocess.run(
            [settings.TRIVY_BINARY_PATH, "--version"],
            capture_output=True,
            text=True,
            check=True
        )
        # Parse version from stdout, e.g., "Version: 0.44.0"
        for line in result.stdout.splitlines():
            if "Version:" in line:
                return line.split("Version:")[1].strip()
        return "unknown"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"

def run_trivy_scan(
    target_path: Path,
    output_path: Path,
    scanners: List[ScannerType],
    severities: List[Severity],
    ignore_unfixed: bool,
    timeout_seconds: int
) -> int:
    """
    Executes trivy fs scan.
    Returns exit code.
    Raises TrivyScanError on timeout or execution failure.
    """
    cmd = [
        settings.TRIVY_BINARY_PATH,
        "fs",
        "--format", "json",
        "--quiet",
        "--output", str(output_path),
        "--scanners", ",".join([s.value for s in scanners]),
        "--severity", ",".join([s.value for s in severities]),
        "--cache-dir", settings.TRIVY_CACHE_DIR
    ]

    if ignore_unfixed:
        cmd.append("--ignore-unfixed")

    cmd.append(str(target_path))

    logger.info(f"Running trivy command: {' '.join(cmd)}")

    try:
        # Using subprocess.run for simplicity since we want to block until done (or timeout)
        # In an async context, we might want to run this in a thread executor if it blocks the event loop too long,
        # but subprocess.run itself releases the GIL for the wait.
        # However, for true async FastAPI, we should wrap this.
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False # We handle exit codes manually
        )
        
        if result.stderr:
            logger.warning(f"Trivy stderr: {result.stderr}")
            
        return result.returncode

    except subprocess.TimeoutExpired:
        logger.error(f"Trivy scan timed out after {timeout_seconds}s")
        raise TrivyScanError(f"Scan timed out after {timeout_seconds} seconds")
    except Exception as e:
        logger.error(f"Trivy execution failed: {e}")
        raise TrivyScanError(f"Trivy execution failed: {str(e)}")
