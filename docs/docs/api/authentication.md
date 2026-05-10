---
sidebar_position: 1
---

# Authentifizierung

Die API nutzt JWT Bearer Tokens.

## Token erhalten

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.de",
  "password": "password"
}
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

## Token verwenden

```http
GET /api/v1/findings
Authorization: Bearer eyJ...
```

## API-Key (für Integrationen)

```http
GET /api/v1/findings
X-API-Key: easm_sk_...
```

## OpenAPI / Swagger UI

Die vollständige interaktive API-Dokumentation ist unter `/api/docs` erreichbar.
