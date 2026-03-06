#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
EMAIL="${EMAIL:-smoke+checkapi@example.com}"

echo "[1/7] health"
curl -fsS "$BASE_URL/health" >/tmp/checkapi_health.json
cat /tmp/checkapi_health.json

echo "[2/7] mcp discovery"
curl -fsS "$BASE_URL/.well-known/mcp/servers.json" >/tmp/checkapi_mcp_servers.json
cat /tmp/checkapi_mcp_servers.json | head -c 300; echo

echo "[3/7] llms"
curl -fsS "$BASE_URL/llms.txt" >/tmp/checkapi_llms.txt
head -n 8 /tmp/checkapi_llms.txt

echo "[4/7] signup"
API_KEY=$(curl -fsS -X POST "$BASE_URL/api/signup" -H "Content-Type: application/json" --data "{\"email\":\"$EMAIL\"}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["api_key"])')
echo "API_KEY=$API_KEY"

echo "[5/7] single check"
curl -fsS -X POST "$BASE_URL/v1/check" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  --data '{"text":"We process health data and biometric data with no explicit retention period.","regulations":["gdpr","hipaa"]}' >/tmp/checkapi_check.json
cat /tmp/checkapi_check.json | head -c 450; echo

echo "[6/7] usage"
curl -fsS "$BASE_URL/v1/usage" -H "Authorization: Bearer $API_KEY" >/tmp/checkapi_usage.json
cat /tmp/checkapi_usage.json

echo "[7/7] MCP tools list"
curl -fsS "$BASE_URL/v1/mcp/tools" >/tmp/checkapi_tools.json
cat /tmp/checkapi_tools.json | head -c 400; echo

echo "Smoke test passed"
