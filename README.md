# Firefly OpenCore Banking Platform — lib-idp-keycloak-impl

Identity Provider (IdP) adapter that implements the Firefly lib-idp port using Keycloak. It exposes a reactive (Spring WebFlux) REST API for authentication and authorization and provides an administrative surface for user, role, scope, session, and MFA management.


---

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Configuration](#configuration)
  - [Key properties](#key-properties)
  - [Profiles](#profiles)
  - [Example application.yaml](#example-applicationyaml)
- [Build and Run](#build-and-run)
- [API](#api)
  - [User endpoints](#user-endpoints)
  - [Admin endpoints](#admin-endpoints)
  - [Examples](#examples)
- [Security and CORS](#security-and-cors)
- [Development Notes](#development-notes)
- [Troubleshooting](#troubleshooting)
- [Versioning](#versioning)
- [Contributing](#contributing)
- [License](#license)

---

## Overview
This repository provides the Keycloak-backed implementation of the Firefly lib-idp adapter. Within a hexagonal (ports-and-adapters) architecture, it delegates identity operations to a configured Keycloak realm and presents a consistent HTTP/JSON interface for Firefly services.

What this project is:
- An adapter of the Firefly lib-idp port backed by Keycloak
- A focused service exposing consistent IdP APIs for Firefly components
- Reactive (non-blocking) using Spring WebFlux

What this project is not:
- A user-facing identity UI
- A replacement for Keycloak server configuration/operations

## Architecture
- Ports: Provided by the upstream dependency `com.catalis:lib-idp-adapter` (DTOs and `IdpAdapter` interface)
- Adapter/Implementation: This repository implements `IdpAdapter` using Keycloak Admin Client APIs
- Transport: HTTP/JSON over Spring WebFlux
- Config: Strongly-typed via `KeycloakProperties`

Packages of interest:
- `com.catalis.idp.adapter.controller` — REST controller layer (public API)
- `com.catalis.idp.adapter.service.*` — user/admin/token services
- `com.catalis.idp.adapter.keycloak.*` — factories and integration with Keycloak
- `com.catalis.idp.properties` — Keycloak properties binding
- `com.catalis.idp.adapter.exception` — exception handling

## Requirements
- Java 21+
- Maven 3.9+
- Access to a Keycloak server (tested with 26.x)

## Configuration
Application uses `application.yaml` with environment-variable overrides. All Keycloak properties are under the `keycloak` prefix.

### Key properties
- `keycloak.server-url` (env: `KEYCLOAK_SERVER_URL`) — Base URL to Keycloak, e.g., `http://localhost:8080`
- `keycloak.realm` (env: `KEYCLOAK_REALM`) — Realm name, e.g., `testrealm`
- `keycloak.client-id` (env: `KEYCLOAK_CLIENT_ID`) — Client ID
- `keycloak.client-secret` (env: `KEYCLOAK_CLIENT_SECRET`) — Client secret (if applicable)
- `keycloak.connection-pool-size` (env: `KEYCLOAK_CONNECTION_POOL_SIZE`) — Default `10`
- `keycloak.connection-timeout` (env: `KEYCLOAK_CONNECTION_TIMEOUT`) — Milliseconds, default `30000`
- `keycloak.request-timeout` (env: `KEYCLOAK_REQUEST_TIMEOUT`) — Milliseconds, default `60000`

Other runtime settings:
- `server.port` — defaults to `8085`

### Profiles
- `dev` — developer-friendly logs
- `testing` — enables OpenAPI/Swagger UI
- `prod` — production-lean logging; Swagger disabled

### Example application.yaml
```yaml
keycloak:
  server-url: ${KEYCLOAK_SERVER_URL:http://localhost:8080}
  realm: ${KEYCLOAK_REALM:testrealm}
  client-id: ${KEYCLOAK_CLIENT_ID:myapp-client}
  client-secret: ${KEYCLOAK_CLIENT_SECRET:change-me}
  connection-pool-size: ${KEYCLOAK_CONNECTION_POOL_SIZE:10}
  connection-timeout: ${KEYCLOAK_CONNECTION_TIMEOUT:30000}
  request-timeout: ${KEYCLOAK_REQUEST_TIMEOUT:60000}
```

## Build and Run
Using Maven:
- Build: `mvn -U -DskipTests clean package`
- Run (from sources): `mvn spring-boot:run`
- Run (from jar): `java -jar target/lib-idp-keycloak-impl-1.0.0-SNAPSHOT.jar`

Activate a profile (example: dev):
- `mvn spring-boot:run -Dspring-boot.run.profiles=dev`
- or `java -Dspring.profiles.active=dev -jar target/lib-idp-keycloak-impl-1.0.0-SNAPSHOT.jar`

## API
Base path: `/idp`

### User endpoints
- POST `/idp/login` — Authenticate and obtain tokens
- POST `/idp/refresh` — Refresh access token using a refresh token
- POST `/idp/logout` — Invalidate the current access token
- GET `/idp/introspect` — Introspect access token
- GET `/idp/userinfo` — Retrieve user info for access token
- POST `/idp/revoke-refresh-token?refreshToken=...` — Revoke a refresh token

### Admin endpoints
- POST `/idp/admin/users` — Create user
- PUT `/idp/admin/users` — Update user
- DELETE `/idp/admin/users/{userId}` — Delete user
- GET `/idp/admin/users/{userId}/roles` — List user roles
- POST `/idp/admin/roles` — Create roles
- POST `/idp/admin/scopes` — Create scope
- POST `/idp/admin/users/roles/assign` — Assign roles to user
- POST `/idp/admin/users/roles/remove` — Remove roles from user
- POST `/idp/admin/password` — Change password
- POST `/idp/admin/password/reset?username=...` — Reset password
- GET `/idp/admin/users/{userId}/sessions` — List user sessions
- DELETE `/idp/admin/sessions/{sessionId}` — Revoke session
- POST `/idp/admin/mfa/challenge?username=...` — Trigger MFA challenge
- POST `/idp/admin/mfa/verify` — Verify MFA challenge

Notes:
- Request/response DTOs are provided by the upstream `lib-idp-adapter` module (package `com.catalis.idp.dtos`). Consult that module for exact schema.
- Authorization header: Use `Authorization: Bearer <access_token>` where applicable.

### Examples
Login:
```bash
curl -X POST http://localhost:8085/idp/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret"}'
```

Introspect:
```bash
curl -X GET http://localhost:8085/idp/introspect \
  -H 'Authorization: Bearer <access_token>'
```

Logout:
```bash
curl -X POST http://localhost:8085/idp/logout \
  -H 'Authorization: Bearer <access_token>'
```

## Security and CORS
- CORS is enabled via a permissive configuration (`CorsWebFilter`). Adjust allowed origins/headers/methods for production.
- Access tokens and refresh tokens are masked in logs where applicable.
- Swagger/OpenAPI is enabled only in the `testing` profile by default.

## Development Notes
- Reactive stack: Spring WebFlux
- DTOs and adapter port come from `com.catalis:lib-idp-adapter`
- MapStruct is used for mappings where needed; Lombok reduces boilerplate

## Troubleshooting
- 401/403: verify realm, client credentials, token audience/scope
- Timeouts: tune `keycloak.connection-timeout` and `keycloak.request-timeout`
- Connectivity: check `keycloak.server-url` and Keycloak availability

## Versioning
- Maven coordinates: `com.catalis:lib-idp-keycloak-impl:1.0.0-SNAPSHOT`
- Java version: 21

## Contributing
Issues and PRs are welcome. Please include clear reproduction steps and tests when applicable.

## License
Licensed under the Apache License, Version 2.0. See the LICENSE file for details.