#!/bin/sh
# =============================================================================
# entrypoint-api.sh
# Läuft Alembic-Migrationen, dann startet Uvicorn
# =============================================================================
set -e

echo "[entrypoint] Warte auf PostgreSQL..."
until python -c "
import psycopg2, os
psycopg2.connect(os.environ['DATABASE_URL'])
print('PostgreSQL bereit')
" 2>/dev/null; do
    sleep 2
done


# Warnung wenn Default-Secret-Key verwendet wird
if [ "${SECRET_KEY}" = "please-set-a-real-secret-key-in-env" ] || [ -z "${SECRET_KEY}" ]; then
    echo "⚠️  WARNING: SECRET_KEY is not set! Set it in your environment/dashboard."
    echo "   Generate one with: openssl rand -hex 32"
fi

echo "[entrypoint] Führe Alembic-Migrationen aus..."
alembic upgrade head

echo "[entrypoint] Starte Uvicorn..."
exec uvicorn api.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers "${UVICORN_WORKERS:-4}" \
    --log-level "${LOG_LEVEL:-info}"
