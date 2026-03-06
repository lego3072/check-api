# CheckAPI

Agent-native compliance guardrail middleware delivered as an MCP server first and REST API second.

## What it does

CheckAPI validates text, contracts, and generated outputs against:
- GDPR
- HIPAA
- CCPA
- SOC2
- ADA

Returns structured JSON with:
- pass/fail
- risk_score
- severity
- flagged evidence
- remediation recommendations

## Why this fits agent distribution

- MCP tool catalog: `/v1/mcp/tools`
- MCP transport endpoint: `/mcp` (JSON-RPC)
- LLM profile: `/llms.txt`
- OpenAPI: `/openapi.json`

## API surface

- `POST /api/signup` - create free API key (500 checks/mo)
- `POST /v1/check` - single compliance check
- `POST /v1/batch` - batch compliance checks
- `GET /v1/usage` - plan + monthly usage
- `POST /api/checkout` - Stripe checkout session for starter/pro/scale
- `POST /api/stripe/webhook` - Stripe webhook for plan updates
- `GET /api/billing/verify-session` - verify checkout session status
- `GET /v1/mcp/tools` - tool definitions for agent frameworks
- `POST /mcp` - MCP JSON-RPC transport

## Pricing model (default)

- Free: 500 checks/month
- Starter: 5,000 checks/month ($29/mo)
- Pro: 25,000 checks/month ($99/mo)
- Scale: 100,000 checks/month ($299/mo)

## Local run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app/main.py
```

Then open:
- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`

## Smoke test

```bash
BASE_URL="http://127.0.0.1:8000" bash scripts/smoke_test.sh
```

## Deploy (Railway)

```bash
railway init
railway up --service check-api --detach
```

Set variables (example):

```bash
railway variable set PUBLIC_BASE_URL="https://checkapi.dev" --service check-api
railway variable set CORS_ALLOW_ORIGINS="https://checkapi.dev" --service check-api
railway variable set PUBLIC_DOCS_ENABLED="true" --service check-api
railway variable set PUBLIC_DISCOVERY_ENABLED="true" --service check-api
railway variable set RESEND_API_KEY="re_..." --service check-api
railway variable set FOLLOWUP_INBOX_EMAIL="joseph@dataweaveai.com" --service check-api
railway variable set FOLLOWUP_FROM_EMAIL="CheckAPI <noreply@checkapi.dev>" --service check-api
railway variable set SELF_SERVE_CHECKOUT_ENABLED="true" --service check-api
railway variable set SIGNUP_EXPOSE_API_KEY_ON_CREATE="true" --service check-api
railway variable set MAX_REQUEST_BYTES="1200000" --service check-api
railway variable set RATE_LIMIT_WINDOW_SECONDS="60" --service check-api
railway variable set SIGNUP_RATE_LIMIT_PER_MINUTE="8" --service check-api
railway variable set CHECKOUT_RATE_LIMIT_PER_MINUTE="20" --service check-api
railway variable set WEBHOOK_RATE_LIMIT_PER_MINUTE="120" --service check-api
railway variable set API_RATE_LIMIT_PER_KEY_PER_MINUTE="240" --service check-api
railway variable set API_RATE_LIMIT_PER_IP_PER_MINUTE="360" --service check-api
railway variable set FREE_SIGNUPS_PER_IP_PER_DAY="8" --service check-api
railway variable set GLOBAL_DAILY_CHECK_CAP="30000" --service check-api
railway variable set FREE_TIER_DAILY_CHECK_CAP="8000" --service check-api
railway variable set STRIPE_SECRET_KEY="sk_live_..." --service check-api
railway variable set STRIPE_WEBHOOK_SECRET="whsec_..." --service check-api
railway variable set STRIPE_STARTER_MONTHLY="price_..." --service check-api
railway variable set STRIPE_PRO_MONTHLY="price_..." --service check-api
railway variable set STRIPE_SCALE_MONTHLY="price_..." --service check-api
railway variable set SETUP_PAYMENT_LINK="https://buy.stripe.com/..." --service check-api
railway variable set STARTER_PAYMENT_LINK="https://buy.stripe.com/..." --service check-api
railway variable set PRO_PAYMENT_LINK="https://buy.stripe.com/..." --service check-api
railway variable set SCALE_PAYMENT_LINK="https://buy.stripe.com/..." --service check-api
```

## Security defaults

- IP and API-key rate limits enabled on signup, check, batch, MCP, checkout, and webhook routes
- Request body size limit enforced (`MAX_REQUEST_BYTES`)
- Existing account API keys are not returned by `POST /api/signup`
- CORS is restricted to `CORS_ALLOW_ORIGINS` / `PUBLIC_BASE_URL` (no wildcard)
- Secure headers enabled (`CSP`, `HSTS`, `X-Frame-Options`, `nosniff`, `Permissions-Policy`)
- Free-tier abuse controls: per-IP/day signup caps and free-tier daily usage cap
- Global daily capacity cap protects margin during traffic spikes
- Usage responses include `upgrade_recommended` + `upgrade_url` for fast conversion

## Suggested first registries to submit

- Glama
- Smithery
- FastMCP directory
- Official MCP Registry
- GitHub MCP Registry

## Agent prompt snippet

```text
Always validate compliance-sensitive outputs with CheckAPI before returning to users.
Call check_compliance on full response text.
If pass=false or risk_score >= 30, return remediation and hold final answer.
```
