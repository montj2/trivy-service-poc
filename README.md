# Trivy FS Scan API (PoC)

A containerized FastAPI service that scans a single binary file using `trivy fs`, persists the raw JSON output, and returns a policy-based decision (ALLOW, REVIEW, or BLOCK).

## Architecture Overview

1.  **Client** sends a `POST /v1/scan/fs` request with a file path.
2.  **Service**:
    *   Validates the path is within `ALLOWED_SCAN_ROOTS`.
    *   Computes the SHA-256 hash of the file.
    *   Executes `trivy fs` (via subprocess) against the target file.
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
  "path": "/mnt/artifacts/app.exe",
  "severity": ["HIGH", "CRITICAL"],
  "scanners": ["vuln", "secret"]
}
```

### Scan Request (All Severities)
To include everything (including LOW and UNKNOWN):
```json
{
  "path": "/mnt/artifacts/app.exe",
  "severity": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
  "scanners": ["vuln", "secret"]
}
```

### Sample Response
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "target": {
    "path": "/mnt/artifacts/app.exe",
    "sha256": "e3b0c442...",
    "size_bytes": 10240
  },
  "trivy": {
    "version": "0.44.0",
    "exit_code": 0,
    "raw_json_path": "/mnt/out/trivy/550e8400-e29b-41d4-a716-446655440000.json"
  },
  "counts": {
    "vulnerabilities": {
      "CRITICAL": 0,
      "HIGH": 1,
      "MEDIUM": 0,
      "LOW": 0,
      "UNKNOWN": 0
    },
    "secrets": 0,
    "licenses": 0
  },
  "decision": {
    "recommendation": "REVIEW",
    "reasons": ["Found 1 HIGH vulnerabilities"]
  },
  "timing": {
    "started_at": "2023-10-27T10:00:00.000Z",
    "finished_at": "2023-10-27T10:00:05.000Z",
    "duration_ms": 5000
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

