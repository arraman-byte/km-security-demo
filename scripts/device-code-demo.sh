#!/usr/bin/env bash
# RFC 8628 Device Authorization Grant against Keycloak (manual demo).
# Prerequisites: a Keycloak public client with "Device authorization" enabled.
#
# Usage:
#   export KEYCLOAK_BASE_URL=http://localhost:8080
#   export KEYCLOAK_REALM=auth-server
#   export KEYCLOAK_DEVICE_CLIENT_ID=security-demo-device
#   ./scripts/device-code-demo.sh
#
# Open KEYCLOAK_BASE_URL in a browser when prompted, complete login, enter user_code.

set -euo pipefail

KEYCLOAK_BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-auth-server}"
KEYCLOAK_DEVICE_CLIENT_ID="${KEYCLOAK_DEVICE_CLIENT_ID:-security-demo-device}"

WELL_KNOWN="${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration"
echo "Fetching OIDC metadata from: ${WELL_KNOWN}"

DEVICE_AUTH_ENDPOINT="$(curl -fsS "${WELL_KNOWN}" | jq -r '.device_authorization_endpoint')"
TOKEN_ENDPOINT="$(curl -fsS "${WELL_KNOWN}" | jq -r '.token_endpoint')"

if [[ "${DEVICE_AUTH_ENDPOINT}" == "null" || -z "${DEVICE_AUTH_ENDPOINT}" ]]; then
  echo "device_authorization_endpoint missing. Enable device flow for your client in Keycloak."
  exit 1
fi

echo "Requesting device code..."
DEVICE_JSON="$(curl -fsS -X POST "${DEVICE_AUTH_ENDPOINT}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "client_id=${KEYCLOAK_DEVICE_CLIENT_ID}" \
  --data-urlencode 'scope=openid profile email')"

DEVICE_CODE="$(echo "${DEVICE_JSON}" | jq -r '.device_code')"
USER_CODE="$(echo "${DEVICE_JSON}" | jq -r '.user_code')"
VERIFICATION_URI="$(echo "${DEVICE_JSON}" | jq -r '.verification_uri')"
INTERVAL="$(echo "${DEVICE_JSON}" | jq -r '.interval // 5')"
EXPIRES_IN="$(echo "${DEVICE_JSON}" | jq -r '.expires_in')"

echo ""
echo "Visit: ${VERIFICATION_URI}"
echo "Enter code: ${USER_CODE}"
echo "(expires in ${EXPIRES_IN}s, poll interval ${INTERVAL}s)"
echo ""

# Poll token endpoint until authorized or timeout
while true; do
  TOKEN_RESPONSE="$(curl -sS -X POST "${TOKEN_ENDPOINT}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "client_id=${KEYCLOAK_DEVICE_CLIENT_ID}" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    --data-urlencode "device_code=${DEVICE_CODE}")"

  ERROR="$(echo "${TOKEN_RESPONSE}" | jq -r '.error // empty')"
  if [[ -z "${ERROR}" ]]; then
    echo "Token response received (access token is not printed)."
    echo "${TOKEN_RESPONSE}" | jq 'del(.access_token, .refresh_token, .id_token)'
    exit 0
  fi

  if [[ "${ERROR}" == "authorization_pending" || "${ERROR}" == "slow_down" ]]; then
    sleep "${INTERVAL}"
    continue
  fi

  if [[ "${ERROR}" == "expired_token" ]]; then
    echo "Device code expired."
    exit 1
  fi

  echo "Token endpoint error: ${ERROR}"
  echo "${TOKEN_RESPONSE}" | jq .
  exit 1
done
