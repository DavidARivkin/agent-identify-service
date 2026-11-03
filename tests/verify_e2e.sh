#!/usr/bin/env bash
set -e

BASE_URL="${SERVICE_BASE_URL:-http://localhost:8080}"

echo "=========================================================="
echo " Running Agent Identity Service Verification Test Suite"
echo " Target: $BASE_URL"
echo "=========================================================="

echo "[1/7] Testing /healthz..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/healthz")
if [ "$STATUS" -ne 200 ]; then echo "FAIL: /healthz returned $STATUS"; exit 1; fi
echo "  ✓ /healthz: 200 OK"

echo "[2/7] Testing /readyz..."
READYZ=$(curl -s "$BASE_URL/readyz")
echo "  ✓ /readyz response: $READYZ"

echo "[3/7] Registering test agent..."
AGENT_JSON=$(curl -s -X POST "$BASE_URL/v1/agents" \
  -H "content-type: application/json" \
  -d '{"agent_name":"e2e-agent","owner":"test-harness","allowed_scopes":["data:read","data:write"]}')
AGENT_ID=$(echo "$AGENT_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['agent_id'])")
SPIFFE_ID=$(echo "$AGENT_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['spiffe_id'])")
echo "  ✓ Registered agent ID: $AGENT_ID ($SPIFFE_ID)"

echo "[4/7] Defining policy..."
POLICY_JSON=$(curl -s -X POST "$BASE_URL/v1/policies" \
  -H "content-type: application/json" \
  -d "{\"spiffe_id\":\"$SPIFFE_ID\",\"resource\":\"data\",\"action\":\"read\",\"effect\":\"allow\"}")
echo "  ✓ Policy created: $POLICY_JSON"

echo "[5/7] Minting JWT-SVID..."
SVID_JSON=$(curl -s -X POST "$BASE_URL/v1/svids" \
  -H "content-type: application/json" \
  -d "{\"agent_id\":\"$AGENT_ID\",\"requested_scopes\":[\"data:read\"],\"audience\":\"agent-platform\",\"ttl_seconds\":300}")
TOKEN=$(echo "$SVID_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
echo "  ✓ JWT-SVID minted successfully"

echo "[6/7] Authorizing request with JWT-SVID..."
AUTH_RES=$(curl -s -X POST "$BASE_URL/v1/authorize" \
  -H "content-type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"resource":"data","action":"read"}')
ALLOWED=$(echo "$AUTH_RES" | python3 -c "import sys, json; print(json.load(sys.stdin).get('allowed', False))")
if [ "$ALLOWED" != "True" ]; then echo "FAIL: expected allowed=true, got $AUTH_RES"; exit 1; fi
echo "  ✓ Authorization check passed (allowed=true)"

echo "[7/7] Revoking agent and verifying revocation..."
curl -s -X POST "$BASE_URL/v1/agents/$AGENT_ID/revoke" > /dev/null
REVOKED_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/v1/authorize" \
  -H "content-type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"resource":"data","action":"read"}')
if [ "$REVOKED_STATUS" -ne 401 ]; then echo "FAIL: expected 401 on revoked agent, got $REVOKED_STATUS"; exit 1; fi
echo "  ✓ Immediate revocation verified (HTTP 401 Unauthorized)"

echo "=========================================================="
echo " All Verification Tests Passed Successfully! "
echo "=========================================================="

