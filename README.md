# Trivy FS Scan API (PoC)

A containerized FastAPI service that scans binary artifacts using a **Hybrid Scan Engine**. It dynamically selects the best strategy—standard `trivy fs`, `trivy rootfs`, or auto-extraction—to detect vulnerabilities in "bare" files (JARs, Archives) and project directories.

## Architecture Overview

1.  **Client** sends a `POST /v1/scan/fs` request with a file path.
2.  **Service**:
    *   Validates the path is within `ALLOWED_SCAN_ROOTS`.
    *   Computes the SHA-256 hash of the file.
    *   **Scan Engine**: Determines the artifact type:
        *   **Standard FS**: For text files, lockfiles, and directories.
        *   **Hybrid RootFS**: For bare Java artifacts (`.jar`, `.war`, `.ear`).
        *   **Auto-Extraction**: For compressed packages (`.tgz`, `.whl`).
    *   Executes the appropriate Trivy command logic.
    *   Persists the raw Trivy JSON output to `RAW_OUTPUT_DIR`.
    *   Parses the results and applies tollgate logic (Decision Engine).
3.  **Client** receives a JSON summary including the decision, counts, and scan metadata.

**Note:** This is a Proof of Concept (PoC) intended for internal use without authentication.

## Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ALLOWED_SCAN_ROOTS` | `/mnt/artifacts` | Comma-separated list of allowed root directories for scanning. |
| `RAW_OUTPUT_DIR` | `/mnt/out` | Directory where raw Trivy JSON reports are saved. |
| `TRIVY_CACHE_DIR` | `/var/lib/trivy` | Directory for Trivy vulnerability DB cache. |
| `MAX_CONCURRENT_SCANS` | `2` | Maximum number of concurrent scan operations. |

## Docker Run Example

Build the image:
```bash
docker build -t trivy-scan-api -f docker/Dockerfile .
```

Run the container (ensure you mount the artifacts directory and output directory):
```bash
docker run -d -p 8080:8080 \
  -v /path/to/my/files:/mnt/artifacts:ro \
  -v /path/to/my/output:/mnt/out:rw \
  trivy-scan-api
```

## API Documentation

FastAPI automatically generates interactive API documentation:
- **Swagger UI**: [http://localhost:8080/docs](http://localhost:8080/docs) - Test endpoints directly in your browser.
- **Redoc**: [http://localhost:8080/redoc](http://localhost:8080/redoc) - Alternative comprehensive documentation.

## API Usage

### Health Check
```bash
curl http://localhost:8080/healthz
# {"status":"ok"}
```

### Scan Request (Default)
**POST** `/v1/scan/fs`

```json
{
  "path": "/mnt/artifacts/log4j-core-2.12.1.jar",
  "severity": ["HIGH", "CRITICAL"],
  "scanners": ["vuln", "secret"]
}
```

### Scan Request (All Severities)
To include everything (including LOW and UNKNOWN):
```json
{
  "path": "/mnt/artifacts/lodash-4.17.15.tgz",
  "severity": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
  "scanners": ["vuln", "secret"]
}
```

### Sample Response
```json
{
  "scan_id": "bd69cbb9-1d0f-4505-bb61-ec16ff934bba",
  "target": {
    "path": "/mnt/artifacts/log4j-core-2.12.1.jar",
    "sha256": "885e31a14fc71cb4849e93564d26a221c685a789379ef63cb2d082cedf3c2235",
    "size_bytes": 1674433
  },
  "trivy": {
    "version": "0.68.1",
    "exit_code": 0,
    "raw_json_path": "/mnt/out/trivy/bd69cbb9-1d0f-4505-bb61-ec16ff934bba.json"
  },
  "counts": {
    "vulnerabilities": {
      "CRITICAL": 2,
      "HIGH": 0,
      "MEDIUM": 0,
      "LOW": 0,
      "UNKNOWN": 0
    },
    "secrets": 0,
    "licenses": 0
  },
  "decision": {
    "recommendation": "BLOCK",
    "reasons": ["Found 2 CRITICAL vulnerabilities"]
  },
  "timing": {
    "started_at": "2025-12-12T08:03:49.712598",
    "finished_at": "2025-12-12T08:03:49.775007",
    "duration_ms": 62
  }
}
```

## Binary Artifact Support
The service implements specialized logic to scan "bare" binary artifacts that are not part of a project structure:

*   **Java (JAR/WAR/EAR)**: Scanned using `trivy rootfs` via a "Hybrid Scan" strategy to detect vulnerabilities in dependencies (e.g., inside `BOOT-INF/lib`).
*   **NPM (.tgz) & PyPI (.whl)**: Automatically extracted to a temporary secure directory and scanned in expanded form to detect `package.json` and metadata vulnerabilities.
*   **Other Binaries (EXE, RPM)**: Currently not supported directly (decision depends on generic Trivy capabilities for these formats).

## Known Limitations

*   **Binary CVE Detection**: Identification of vulnerabilities in compiled binaries is best-effort and depends on Trivy's ability to analyze the specific binary format/metadata.
*   **Security**: No authentication or extensive input sanitization beyond path validation (Internal PoC only).
*   **Single File**: The API currently supports only single file scanning (except for supported Archives which are auto-expanded).

