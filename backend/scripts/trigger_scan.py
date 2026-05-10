#!/usr/bin/env python3
"""
trigger_scan.py — Manuell einen Scan für eine Domain starten
Aufruf: docker compose exec api python -m scripts.trigger_scan example.de
"""
import sys, os
sys.path.insert(0, '/app')

from workers.toolchain_tasks import schedule_tenants

domain = sys.argv[1] if len(sys.argv) > 1 else None
if not domain:
    print("Usage: python -m scripts.trigger_scan <domain>")
    sys.exit(1)

print(f"Triggering full scan for: {domain}")
result = schedule_tenants.delay("all", "full")
print(f"Task ID: {result.id}")
print("Monitor at: flower.YOUR_DOMAIN or make logs")
