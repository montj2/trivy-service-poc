#!/bin/bash
set -e

# Define directories
CACHE_DIR="/var/lib/trivy"
BAKED_DB_DIR="/usr/share/trivy-baked"

# Check if the cache directory is empty (checking for db dir specifically to be safe)
if [ ! -d "$CACHE_DIR/db" ] && [ -d "$BAKED_DB_DIR" ]; then
    echo "[Entrypoint] Initializing Trivy DB from baked-in cache..."
    # Copy contents. 
    # Note: We use cp -rn to avoid overwriting if partial data exists, 
    # but strictly we want to seed if empty.
    cp -R "$BAKED_DB_DIR/"* "$CACHE_DIR/" 2>/dev/null || true
    echo "[Entrypoint] DB initialization complete."
fi

# Execute the CMD
exec "$@"
