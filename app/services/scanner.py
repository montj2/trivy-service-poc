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

import tarfile
import zipfile
import tempfile
import shutil

def extract_archive(archive_path: Path, target_dir: Path) -> bool:
    """
    Extracts supported archives (.tgz, .tar.gz, .whl) to target_dir.
    Returns True if extracted, False if not supported or failed.
    """
    path_str = str(archive_path).lower()
    
    try:
        if path_str.endswith(".tgz") or path_str.endswith(".tar.gz"):
            with tarfile.open(archive_path, "r:gz") as tar:
                # Security: Basic filter to prevent zip bombs/traversal 
                # (tarfile.data_filter introduced in 3.12 is best, but defaulting to 'data' for safety)
                if hasattr(tarfile, 'data_filter'):
                    tar.extractall(path=target_dir, filter='data')
                else:
                    # Fallback for older python, though we are on 3.12 in Docker
                    tar.extractall(path=target_dir) 
            return True
            
        elif path_str.endswith(".whl"):
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                zip_ref.extractall(target_dir)
            return True
            
    except (tarfile.TarError, zipfile.BadZipFile, OSError) as e:
        logger.error(f"Failed to extract archive {archive_path}: {e}")
        return False
        
    return False

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
    cmd_mode = "fs"
    scan_target = str(target_path)
    temp_extract_dir = None

    # Determine if auto-extraction is needed
    if target_path.name.lower().endswith((".tgz", ".tar.gz", ".whl")):
        temp_extract_dir = tempfile.mkdtemp(prefix="trivy_extract_")
        extract_success = extract_archive(target_path, Path(temp_extract_dir))
        
        if extract_success:
            logger.info(f"Successfully extracted {target_path} to {temp_extract_dir}")
            scan_target = temp_extract_dir
            # Always use fs mode for extracted directories
            cmd_mode = "fs" 
        else:
            logger.warning(f"Failed to extract {target_path}, falling back to direct file scan")
            shutil.rmtree(temp_extract_dir, ignore_errors=True)
            temp_extract_dir = None

    # Existing logic: RootFS fallback for bare Java artifacts (only if NOT extracted)
    elif target_path.suffix.lower() in [".jar", ".war", ".ear"]:
        cmd_mode = "rootfs"

    cmd = [
        settings.TRIVY_BINARY_PATH,
        cmd_mode,
        "--format", "json",
        "--quiet",
        "--output", str(output_path),
        "--scanners", ",".join([s.value for s in scanners]),
        "--severity", ",".join([s.value for s in severities]),
        "--cache-dir", settings.TRIVY_CACHE_DIR
    ]

    if ignore_unfixed:
        cmd.append("--ignore-unfixed")

    cmd.append(scan_target)

    logger.info(f"Running trivy command: {' '.join(cmd)}")

    try:
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
    finally:
        # Cleanup extracted files if they were created
        if temp_extract_dir and Path(temp_extract_dir).exists():
            shutil.rmtree(temp_extract_dir, ignore_errors=True)
            logger.info(f"Cleaned up temporary extraction directory: {temp_extract_dir}")
