#!/usr/bin/env bash

set -euo pipefail

STACK_ENV_FILE="${1:-deploy/stack.env}"
EXPORT_DIR="deploy/keycloak/export"

if [[ ! -f "$STACK_ENV_FILE" ]]; then
  echo "Env file not found: $STACK_ENV_FILE" >&2
  echo "Copy deploy/stack.env.example to deploy/stack.env and update it first." >&2
  exit 1
fi

mkdir -p "$EXPORT_DIR"

set -a
source "$STACK_ENV_FILE"
set +a

echo "Stopping Keycloak before export to avoid H2 file locking issues..."
docker compose --env-file "$STACK_ENV_FILE" stop keycloak

echo "Exporting realm ${KEYCLOAK_REALM:-uyuni-mcp} to $EXPORT_DIR/..."
docker compose --env-file "$STACK_ENV_FILE" --profile ops run --rm keycloak-export

echo "Starting Keycloak again..."
docker compose --env-file "$STACK_ENV_FILE" up -d keycloak

echo "Realm export completed."