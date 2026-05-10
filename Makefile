# =============================================================================
# EASM MSSP Platform — Makefile
# =============================================================================
dev: ## Startet die Entwicklungsumgebung lokal ohne TLS (localhost:3000)
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
	@echo ""
	@echo "  Frontend:  http://localhost:3000"
	@echo "  API:       http://localhost:8000/docs"
	@echo "  Flower:    http://localhost:5555"

seed: ## Demo-Daten in DB laden
	docker exec easm-api python /app/scripts/seed_demo.py

.PHONY: help up down build dev logs ps migrate seed scan update-nuclei \
        backup-db restore-db shell-api shell-db shell-worker clean

COMPOSE         = docker compose
COMPOSE_DEV     = docker compose -f docker-compose.yml -f docker-compose.dev.yml
DOMAIN          ?= example.de

# ── Help ──────────────────────────────────────────────────────────────────────
help: ## Diese Hilfe anzeigen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Lifecycle ─────────────────────────────────────────────────────────────────
up: ## Alle Services starten
	$(COMPOSE) up -d
	@echo ""
	@echo "✓ Platform gestartet. Warte ~60s bis alle Services bereit sind."
	@echo "  Frontend:  https://$$(grep APP_DOMAIN .env | cut -d= -f2)"
	@echo "  Flower:    https://flower.$$(grep APP_DOMAIN .env | cut -d= -f2)"

down: ## Alle Services stoppen
	$(COMPOSE) down

restart: ## Alle Services neu starten
	$(COMPOSE) restart

build: ## Alle Docker-Images bauen
	$(COMPOSE) build --parallel
	@echo "✓ Images gebaut"

build-no-cache: ## Images ohne Cache neu bauen (nach grossen Updates)
	$(COMPOSE) build --no-cache --parallel

pull: ## Base-Images aktualisieren
	$(COMPOSE) pull

# ── Development ───────────────────────────────────────────────────────────────
dev: ## Dev-Modus: Hot-Reload API + Frontend, DB-Port offen
	$(COMPOSE_DEV) up -d
	@echo "✓ Dev-Modus aktiv"
	@echo "  API:      http://localhost:8000"
	@echo "  Frontend: http://localhost:3000"
	@echo "  DB:       localhost:5432"

dev-down: ## Dev-Services stoppen
	$(COMPOSE_DEV) down

# ── Logs ─────────────────────────────────────────────────────────────────────
logs: ## Live-Log aller Services
	$(COMPOSE) logs -f --tail=100

logs-api: ## API-Log
	$(COMPOSE) logs -f api --tail=100

logs-worker: ## Worker-Log
	$(COMPOSE) logs -f worker-scan worker-hibp worker-alerts --tail=100

logs-scan: ## Scan-Worker-Log
	$(COMPOSE) logs -f worker-scan --tail=200

ps: ## Status aller Services
	$(COMPOSE) ps

# ── Database ─────────────────────────────────────────────────────────────────
migrate: ## Alembic-Migrationen ausführen
	$(COMPOSE) exec api alembic upgrade head
	@echo "✓ Migrationen abgeschlossen"

migrate-status: ## Aktueller Migrationsstatus
	$(COMPOSE) exec api alembic current
	$(COMPOSE) exec api alembic history

migrate-rollback: ## Letzte Migration rückgängig machen
	$(COMPOSE) exec api alembic downgrade -1

seed: ## Demo-Mandanten und Admin-User erstellen
	$(COMPOSE) exec api python -m scripts.seed_demo
	@echo "✓ Demo-Daten erstellt"

backup-db: ## Datenbankbackup erstellen
	@mkdir -p backups
	$(COMPOSE) exec postgres pg_dump \
		-U $$(grep POSTGRES_USER .env | cut -d= -f2) \
		$$(grep POSTGRES_DB .env | cut -d= -f2) \
		| gzip > backups/easm_$$(date +%Y%m%d_%H%M%S).sql.gz
	@echo "✓ Backup erstellt: backups/easm_$$(date +%Y%m%d).sql.gz"

restore-db: ## Backup einspielen: make restore-db BACKUP=backups/easm_xyz.sql.gz
	@test -n "$(BACKUP)" || (echo "Fehler: make restore-db BACKUP=<pfad>" && exit 1)
	gunzip -c $(BACKUP) | $(COMPOSE) exec -T postgres psql \
		-U $$(grep POSTGRES_USER .env | cut -d= -f2) \
		$$(grep POSTGRES_DB .env | cut -d= -f2)
	@echo "✓ Backup eingespielt: $(BACKUP)"

shell-db: ## psql-Shell in PostgreSQL
	$(COMPOSE) exec postgres psql \
		-U $$(grep POSTGRES_USER .env | cut -d= -f2) \
		$$(grep POSTGRES_DB .env | cut -d= -f2)

# ── Scans ─────────────────────────────────────────────────────────────────────
scan: ## Manuellen Scan starten: make scan DOMAIN=example.de
	@test -n "$(DOMAIN)" || (echo "Fehler: make scan DOMAIN=example.de" && exit 1)
	$(COMPOSE) exec api python -m scripts.trigger_scan $(DOMAIN)

scan-mcp: ## Nur MCP-Scan: make scan-mcp DOMAIN=example.de
	@test -n "$(DOMAIN)" || (echo "Fehler: make scan-mcp DOMAIN=example.de" && exit 1)
	$(COMPOSE) exec api python -m scripts.trigger_scan $(DOMAIN) mcp_only

update-nuclei: ## Nuclei-Templates manuell aktualisieren
	$(COMPOSE) exec worker-scan nuclei -update-templates
	@echo "✓ Nuclei-Templates aktualisiert"

# ── Shell-Zugang ─────────────────────────────────────────────────────────────
shell-api: ## Shell im API-Container
	$(COMPOSE) exec api bash

shell-worker: ## Shell im Scan-Worker
	$(COMPOSE) exec worker-scan bash

# ── Monitoring ───────────────────────────────────────────────────────────────
flower: ## Celery-Monitoring URL anzeigen
	@echo "Flower: https://flower.$$(grep APP_DOMAIN .env | cut -d= -f2)"

# ── Updates ──────────────────────────────────────────────────────────────────
update: ## Plattform aktualisieren (git pull + rebuild)
	git pull origin main
	$(COMPOSE) build --parallel
	$(COMPOSE) up -d --no-deps api
	$(COMPOSE) up -d --no-deps worker-scan worker-hibp worker-alerts
	$(COMPOSE) up -d --no-deps frontend
	@echo "✓ Update abgeschlossen"

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean: ## Gestoppte Container und ungenutzte Images entfernen
	docker system prune -f
	@echo "✓ Cleanup abgeschlossen"

clean-all: ## VORSICHT: Alle Volumes löschen (Datenverlust!)
	@echo "⚠  WARNUNG: Alle Volumes werden gelöscht!"
	@read -p "Fortfahren? (yes/no): " ans && [ "$$ans" = "yes" ]
	$(COMPOSE) down -v
	docker system prune -f
	@echo "✓ Kompletter Reset"

# ── Setup-Hilfe ──────────────────────────────────────────────────────────────
setup: ## Erstes Setup: .env prüfen, bauen, starten, migrieren
	@test -f .env || (echo "Fehler: .env fehlt. Führe zuerst aus: cp .env.example .env" && exit 1)
	@grep -q "change_me" .env && echo "⚠  Warnung: .env enthält noch Platzhalter-Passwörter!" || true
	$(MAKE) build
	$(MAKE) up
	@echo "Warte 30s auf PostgreSQL..."
	@sleep 30
	$(MAKE) migrate
	$(MAKE) seed
	@echo ""
	@echo "✓ Setup abgeschlossen!"
	@echo "  → Browser: https://$$(grep APP_DOMAIN .env | cut -d= -f2)"
