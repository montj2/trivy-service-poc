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

import os

# Security Limits for Extraction
MAX_EXTRACT_SIZE = 1024 * 1024 * 500  # 500 MB
MAX_EXTRACT_FILES = 10000

def extract_archive(archive_path: Path, target_dir: Path) -> bool:
    """
    Extracts supported archives with security protections (ZipSlip, Quotas).
    Returns True if extracted, False if failed.
    """
    path_str = str(archive_path).lower()
    target_dir_res = target_dir.resolve()
    
    total_size = 0
    total_files = 0
    
    try:
        if path_str.endswith(".tgz") or path_str.endswith(".tar.gz"):
            with tarfile.open(archive_path, "r:gz") as tar:
                # Python 3.12+ data_filter handles traversal/links automatically
                if hasattr(tarfile, 'data_filter'):
                    tar.extractall(path=target_dir, filter='data')
                    # Still need to enforce quotas manually if desired, but 'data' filter is quite safe against system takeover.
                    # Iterating to check quotas on standard tar is tricky without extracting first or iterating members.
                    # Let's iterate members to enforce quotas strictly.
                    for member in tar:
                        if total_files > MAX_EXTRACT_FILES:
                             raise Exception("Too many files in archive")
                        total_files += 1
                        total_size += member.size
                        if total_size > MAX_EXTRACT_SIZE:
                             raise Exception("Archive too large")
                else:
                    # Fallback with manual checks
                    for member in tar:
                        # Safety: Resolve target and check
                        # Note: tarfile.extractall does some of this but member iteration allows quota checks
                        dest = target_dir_res / member.name
                        # Basic ZipSlip check for Tar (though extractall handles most)
                        if not os.path.commonpath([target_dir_res, dest.resolve()]).startswith(str(target_dir_res)):
                            raise Exception("ZipSlip attempt detected")
                        
                        if total_files > MAX_EXTRACT_FILES:
                             raise Exception("Too many files in archive")
                        total_files += 1
                        total_size += member.size
                        if total_size > MAX_EXTRACT_SIZE:
                             raise Exception("Archive too large")
                    
                    # If checks pass, extract
                    tar.extractall(path=target_dir)

            return True
            
        elif path_str.endswith(".whl"):
            with zipfile.ZipFile(archive_path, "r") as z:
                for info in z.infolist():
                    # ZipSlip protection
                    dest = target_dir_res / info.filename
                    if not str(dest.resolve()).startswith(str(target_dir_res)):
                        raise Exception(f"ZipSlip attempt detected: {info.filename}")
                    
                    # Quotas
                    total_files += 1
                    total_size += info.file_size
                    if total_files > MAX_EXTRACT_FILES:
                        raise Exception("Too many files in archive")
                    if total_size > MAX_EXTRACT_SIZE:
                        raise Exception("Archive too large")
                
                # If safe, extract
                z.extractall(target_dir)
            return True
            
    except Exception as e:
        logger.error(f"Failed to extract archive {archive_path.name}: {e}")
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
    
    # Redacted info for logs
    target_name = target_path.name

    # Determine if auto-extraction is needed
    if target_path.name.lower().endswith((".tgz", ".tar.gz", ".whl")):
        temp_extract_dir = tempfile.mkdtemp(prefix="trivy_extract_")
        extract_success = extract_archive(target_path, Path(temp_extract_dir))
        
        if extract_success:
            logger.info(f"Successfully extracted {target_name} to temp dir")
            scan_target = temp_extract_dir
            # Always use fs mode for extracted directories
            cmd_mode = "fs" 
        else:
            logger.warning(f"Failed to extract {target_name}, falling back to direct file scan")
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

    # Log command with redaction
    # We redact the input path and output path for security logs
    safe_cmd = list(cmd)
    safe_cmd[-1] = f"[REDACTED]/{target_name}" # The target
    try:
        # The output path is usually /mnt/out/trivy/uuid.json - uuid is safe enough but lets be consistent
        out_idx = safe_cmd.index("--output") + 1
        safe_cmd[out_idx] = "[REDACTED_JSON_OUTPUT]"
    except (ValueError, IndexError):
        pass

    logger.info(f"Running trivy command: {' '.join(safe_cmd)}")

    logger.info(f"Running trivy command: {' '.join(safe_cmd)}")

    try:
        # Retry loop for RootFS fallback
        for attempt in range(2):
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False 
            )
            
            if result.returncode == 0:
                if result.stderr:
                    logger.warning(f"Trivy stderr: {result.stderr}")
                return 0
            
            # If failed and was rootfs, try fallback to fs
            if cmd[1] == "rootfs" and attempt == 0:
                logger.warning(f"Trivy rootfs scan failed with code {result.returncode}. Retrying with 'fs' mode.")
                if result.stderr:
                    logger.warning(f"RootFS failure stderr: {result.stderr}")
                cmd[1] = "fs"
                # Update logged command for clarity (optional, but good for debugging)
                # safe_cmd matches structure, so update it too
                safe_cmd[1] = "fs" 
                logger.info(f"Retrying trivy command: {' '.join(safe_cmd)}")
                continue
            
            # If we get here, it failed and no fallback left (or not eligible)
            if result.stderr:
                logger.warning(f"Trivy stderr: {result.stderr}")
            return result.returncode

    except subprocess.TimeoutExpired:
        logger.error(f"Trivy scan timed out for {target_name}")
        raise TrivyScanError(f"Scan timed out after {timeout_seconds} seconds")
    except Exception as e:
        logger.error(f"Trivy execution failed for {target_name}: {e}")
        raise TrivyScanError(f"Trivy execution failed: {str(e)}")
    finally:
        # Cleanup extracted files if they were created
        if temp_extract_dir and Path(temp_extract_dir).exists():
            shutil.rmtree(temp_extract_dir, ignore_errors=True)
            logger.info("Cleaned up temporary extraction directory")
