# Deploy Directory

This directory contains the environment files and Keycloak import and export data for the local deployment stack.

This setup is intended for development and test use only. It is not a production deployment.

## Files

- `stack.env.example`: template environment file
- `stack.env`: local runtime configuration
- `keycloak/import/`: Keycloak realm import files used on first boot
- `keycloak/export/`: exported realm files

Related files outside this directory:

- `docker-compose.yml`: local dev/test stack definition
- `scripts/export-keycloak-realm.sh`: export helper for the local Keycloak realm

## Minimal stack.env

Copy the template first:

```bash
cp deploy/stack.env.example deploy/stack.env
```

For a minimal local dev/test setup, set these values:

```env
UYUNI_SERVER=uyuni.example.internal
KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=admin
KEYCLOAK_BOOTSTRAP_ADMIN_PASSWORD=change-me-now
KEYCLOAK_PUBLIC_HOSTNAME=keycloak
UYUNI_MCP_PUBLIC_URL=http://127.0.0.1:8000
UYUNI_AUTH_SERVER=http://keycloak:8080/realms/uyuni-mcp
```

Notes:

- `UYUNI_SERVER` must point to your Uyuni server.
- `UYUNI_AUTH_SERVER` should use the Docker-internal Keycloak URL for this compose stack, not `http://localhost:8080/...`.
- Set `KEYCLOAK_PUBLIC_HOSTNAME=keycloak` so Keycloak and the MCP server use the same hostname in local dev/test.
- If you are testing from the host, map `keycloak` to `127.0.0.1` in your hosts file. Otherwise the browser cannot follow Keycloak redirects correctly.
- Leave the default local ports in `stack.env.example` unchanged unless you also update the related Keycloak hostname and port settings consistently.

## Start

```bash
docker compose --env-file deploy/stack.env up -d --build
```

## Stop

```bash
docker compose --env-file deploy/stack.env down
```

## Reset Keycloak Data

```bash
docker compose --env-file deploy/stack.env down -v
docker compose --env-file deploy/stack.env up -d --build
```

## Export Realm

```bash
./scripts/export-keycloak-realm.sh deploy/stack.env
```
