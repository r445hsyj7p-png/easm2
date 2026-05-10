---
sidebar_position: 2
title: Backups
---

# Backup & Recovery

## Automatische Backups

Der Stack beinhaltet einen dedizierten Backup-Container der täglich um 03:00 UTC läuft:

```yaml
# In docker-compose.yml — bereits konfiguriert
backup:
  image: postgres:16
  command: >
    sh -c "pg_dump $$DATABASE_URL | gzip > /backups/easm_$$(date +%Y%m%d_%H%M%S).sql.gz
    && find /backups -name '*.sql.gz' -mtime +30 -delete"
  volumes:
    - ./backups:/backups
```

**Retention:** 30 Tage lokal. Ältere Backups werden automatisch gelöscht.

## Manuelles Backup

```bash
make backup-db
```

Erstellt `backups/easm_YYYYMMDD_HHMMSS.sql.gz`.

## Optionales S3-Backup

In `.env` konfigurieren:
```env
S3_BACKUP_BUCKET=s3://mein-backup-bucket/easm/
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

Der Backup-Container lädt dann automatisch nach S3 hoch.

## Recovery

```bash
# Backup einspielen
make restore-db BACKUP=backups/easm_20260505_080000.sql.gz

# Oder manuell:
gunzip -c backups/easm_20260505_080000.sql.gz | \
  docker compose exec -T postgres psql -U easm easm
```

## Was gesichert wird

| Was | Wie |
|---|---|
| PostgreSQL-Datenbank | `pg_dump` → .sql.gz |
| Nuclei-Templates | Kein Backup nötig (täglich neu heruntergeladen) |
| Screenshots | Volume `screenshots/` — optional in S3 |
| Reports | Volume `reports/` — optional in S3 |
| `.env` | **Manuell sichern** — enthält alle Secrets |

:::danger
Die `.env`-Datei wird **nicht** automatisch gesichert. Sie enthält alle Passwörter und API-Keys und muss separat und sicher aufbewahrt werden.
:::
