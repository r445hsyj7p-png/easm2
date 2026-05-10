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

# Nuclei-Templates nur beim ersten Start oder täglich updaten
TEMPLATES_DIR="${HOME}/nuclei-templates"
STAMP_FILE="/tmp/.nuclei-updated"
if [ ! -f "$STAMP_FILE" ] || [ "$(find $STAMP_FILE -mtime +1)" ]; then
    echo "[entrypoint] Aktualisiere Nuclei-Templates..."
    nuclei -update-templates -silent || echo "[entrypoint] Template-Update fehlgeschlagen, fahre fort"
    touch "$STAMP_FILE"
fi

echo "[entrypoint] Starte Celery Worker..."
exec "$@"
