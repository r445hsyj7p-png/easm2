#!/bin/sh
# =============================================================================
# entrypoint-worker.sh
# Aktualisiert Nuclei-Templates beim Start, dann Celery
# =============================================================================
set -e

echo "[entrypoint] Warte auf Redis..."
until python -c "
import redis, os
r = redis.from_url(os.environ['REDIS_URL'])
r.ping()
print('Redis bereit')
" 2>/dev/null; do
    sleep 2
done

# ── Nuclei-Templates ──────────────────────────────────────────────────────────
TEMPLATES_DIR="${HOME}/nuclei-templates"
STAMP_FILE="/tmp/.nuclei-updated"

# Update templates once per day or on first start
if [ ! -f "$STAMP_FILE" ] || [ "$(find "$STAMP_FILE" -mtime +1 2>/dev/null)" ]; then
    echo "[entrypoint] Aktualisiere Nuclei-Templates nach ${TEMPLATES_DIR}..."
    # nuclei v3: use default template dir (~/nuclei-templates) so runtime scans find them
    # -ud sets where templates are stored; omit -silent so errors are visible
    nuclei -update-templates -ud "${TEMPLATES_DIR}" 2>&1 || \
    nuclei -ut -ud "${TEMPLATES_DIR}" 2>&1 || \
    echo "[entrypoint] Template-Update fehlgeschlagen — fahre ohne aktuelle Templates fort"
    touch "$STAMP_FILE"
fi

# Verify templates were actually downloaded
TMPL_COUNT=$(find "${TEMPLATES_DIR}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ' || echo 0)
if [ "$TMPL_COUNT" -eq 0 ]; then
    echo "[entrypoint] WARNUNG: Keine Templates in ${TEMPLATES_DIR} — versuche nuclei ohne -ud..."
    nuclei -update-templates 2>&1 || true
fi

# Log template count for diagnostics
TMPL_COUNT=$(find "${TEMPLATES_DIR}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ' || echo 0)
echo "[entrypoint] Nuclei-Templates: ${TMPL_COUNT} .yaml Dateien in ${TEMPLATES_DIR}"

# ── Tool-Verfügbarkeit prüfen ─────────────────────────────────────────────────
for BIN in nuclei subfinder naabu httpx theHarvester; do
    if command -v "$BIN" >/dev/null 2>&1; then
        echo "[entrypoint] ✓ ${BIN} verfügbar"
    else
        echo "[entrypoint] ✗ ${BIN} NICHT gefunden"
    fi
done

echo "[entrypoint] Starte Celery Worker..."
exec "$@"
