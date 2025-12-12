FROM python:3.12-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    apt-transport-https \
    gnupg \
    lsb-release \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy (using modern signed-by method)
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb bookworm main" | tee -a /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y trivy \
    && rm -rf /var/lib/apt/lists/* \
    # Download DBs to a baked location that won't be masked by volumes
    && mkdir -p /usr/share/trivy-baked \
    && trivy image --download-db-only --cache-dir /usr/share/trivy-baked --no-progress \
    && trivy image --download-java-db-only --cache-dir /usr/share/trivy-baked --no-progress

# Setup application directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app ./app
COPY docker/entrypoint.sh /app/entrypoint.sh

# Setup directories and permissions
RUN mkdir -p /mnt/artifacts /mnt/out /var/lib/trivy \
    && groupadd -r appuser && useradd -r -g appuser appuser \
    && chown -R appuser:appuser /mnt/out /var/lib/trivy /app/entrypoint.sh

# Switch to non-root user
USER appuser

# Environment variables
ENV ALLOWED_SCAN_ROOTS=/mnt/artifacts
ENV RAW_OUTPUT_DIR=/mnt/out
ENV TRIVY_CACHE_DIR=/var/lib/trivy

# Default command
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
