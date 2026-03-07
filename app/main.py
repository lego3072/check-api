import json
import os
import re
import secrets
import sqlite3
import hashlib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, redirect, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge

try:
    import stripe
except ImportError:  # pragma: no cover
    stripe = None

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LANDING_DIR = BASE_DIR / "landing"
DB_PATH = DATA_DIR / "check_api.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip()
PUBLIC_DOCS_ENABLED = env_bool("PUBLIC_DOCS_ENABLED", True)
PUBLIC_DISCOVERY_ENABLED = env_bool("PUBLIC_DISCOVERY_ENABLED", True)
PUBLIC_MCP_TOOLS_ENABLED = env_bool("PUBLIC_MCP_TOOLS_ENABLED", False)
INDEXNOW_KEY = os.getenv("INDEXNOW_KEY", "").strip()
CORS_ALLOW_ORIGINS_RAW = os.getenv("CORS_ALLOW_ORIGINS", "").strip()

DATAWEAVE_HOME_URL = os.getenv("DATAWEAVE_HOME_URL", "https://dataweaveai.com").strip()
EXTRACT_API_URL = os.getenv("EXTRACT_API_URL", "https://extractapi.net").strip()
REDACT_API_URL = os.getenv("REDACT_API_URL", "https://redactapi.dev").strip()
AGENT_ROUTER_URL = os.getenv("AGENT_ROUTER_URL", "https://get-agent-router.com").strip()
AGENT_ROUTER_BUNDLE_MONTHLY_URL = os.getenv(
    "AGENT_ROUTER_BUNDLE_MONTHLY_URL", f"{AGENT_ROUTER_URL.rstrip('/')}/api/stripe/bundle-monthly-checkout"
).strip()
AGENT_ROUTER_BUNDLE_FULL_URL = os.getenv(
    "AGENT_ROUTER_BUNDLE_FULL_URL", f"{AGENT_ROUTER_URL.rstrip('/')}/api/stripe/bundle-full-checkout"
).strip()
AGENT_ROUTER_BUNDLE_DASHBOARD_URL = os.getenv(
    "AGENT_ROUTER_BUNDLE_DASHBOARD_URL", f"{AGENT_ROUTER_URL.rstrip('/')}/bundle"
).strip()

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "").strip()
FOLLOWUP_INBOX_EMAIL = os.getenv("FOLLOWUP_INBOX_EMAIL", "joseph@dataweaveai.com").strip()
FOLLOWUP_FROM_EMAIL = os.getenv("FOLLOWUP_FROM_EMAIL", "CheckAPI <noreply@checkapi.dev>").strip()

SETUP_PAYMENT_LINK = os.getenv("SETUP_PAYMENT_LINK", "https://buy.stripe.com/replace_setup_link")
STARTER_PAYMENT_LINK = os.getenv("STARTER_PAYMENT_LINK", "https://buy.stripe.com/replace_starter_link")
PRO_PAYMENT_LINK = os.getenv("PRO_PAYMENT_LINK", "https://buy.stripe.com/replace_pro_link")
SCALE_PAYMENT_LINK = os.getenv("SCALE_PAYMENT_LINK", "https://buy.stripe.com/replace_scale_link")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
STRIPE_STARTER_MONTHLY = os.getenv("STRIPE_STARTER_MONTHLY", "").strip()
STRIPE_PRO_MONTHLY = os.getenv("STRIPE_PRO_MONTHLY", "").strip()
STRIPE_SCALE_MONTHLY = os.getenv("STRIPE_SCALE_MONTHLY", "").strip()
SELF_SERVE_CHECKOUT_ENABLED = env_bool("SELF_SERVE_CHECKOUT_ENABLED", True)
SIGNUP_EXPOSE_API_KEY_ON_CREATE = env_bool("SIGNUP_EXPOSE_API_KEY_ON_CREATE", True)
FREE_SIGNUP_ENABLED = env_bool("FREE_SIGNUP_ENABLED", False)

MAX_TEXT_CHARS_GLOBAL = env_int("MAX_TEXT_CHARS_GLOBAL", 120000)
MAX_REQUEST_BYTES = env_int("MAX_REQUEST_BYTES", 1_200_000)

SIGNUP_RATE_LIMIT_PER_MINUTE = env_int("SIGNUP_RATE_LIMIT_PER_MINUTE", 8)
CHECKOUT_RATE_LIMIT_PER_MINUTE = env_int("CHECKOUT_RATE_LIMIT_PER_MINUTE", 20)
WEBHOOK_RATE_LIMIT_PER_MINUTE = env_int("WEBHOOK_RATE_LIMIT_PER_MINUTE", 120)
API_RATE_LIMIT_PER_KEY_PER_MINUTE = env_int("API_RATE_LIMIT_PER_KEY_PER_MINUTE", 240)
API_RATE_LIMIT_PER_IP_PER_MINUTE = env_int("API_RATE_LIMIT_PER_IP_PER_MINUTE", 360)
RATE_LIMIT_WINDOW_SECONDS = env_int("RATE_LIMIT_WINDOW_SECONDS", 60)

FREE_SIGNUPS_PER_IP_PER_DAY = env_int("FREE_SIGNUPS_PER_IP_PER_DAY", 8)
GLOBAL_DAILY_CHECK_CAP = env_int("GLOBAL_DAILY_CHECK_CAP", 30000)
FREE_TIER_DAILY_CHECK_CAP = env_int("FREE_TIER_DAILY_CHECK_CAP", 8000)

if stripe and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

PLAN_LIMITS = {
    "free": {"checks_per_month": 500, "max_chars": 12000, "batch_limit": 10},
    "starter": {"checks_per_month": 5000, "max_chars": 30000, "batch_limit": 40},
    "pro": {"checks_per_month": 25000, "max_chars": 60000, "batch_limit": 120},
    "scale": {"checks_per_month": 100000, "max_chars": 120000, "batch_limit": 300},
}

STRIPE_PRICE_IDS = {
    "starter": STRIPE_STARTER_MONTHLY,
    "pro": STRIPE_PRO_MONTHLY,
    "scale": STRIPE_SCALE_MONTHLY,
}

SEVERITY_WEIGHT = {
    "low": 5,
    "medium": 12,
    "high": 34,
    "critical": 45,
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
API_KEY_RE = re.compile(r"^ck_[a-f0-9]{48}$")
BLOCKED_CHECKOUT_EMAIL_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "10minutemail.com",
    "yopmail.com",
    "trashmail.com",
    "sharklasers.com",
}
BLOCKED_CHECKOUT_LOCAL_TOKENS = ("test", "fake", "demo", "bot", "spam", "temp", "example")

RULES = [
    {
        "rule_id": "gdpr_special_category_no_basis",
        "regulation": "gdpr",
        "title": "Special category data without legal basis",
        "pattern": re.compile(r"\b(health data|biometric|racial|ethnic|religious belief|sexual orientation)\b", re.IGNORECASE),
        "severity": "high",
        "recommendation": "Document explicit legal basis and add data minimization controls for special category processing.",
    },
    {
        "rule_id": "gdpr_missing_retention",
        "regulation": "gdpr",
        "title": "No data retention period referenced",
        "pattern": re.compile(r"\b(data retention|retention period|delete after|erasure schedule)\b", re.IGNORECASE),
        "severity": "medium",
        "invert": True,
        "recommendation": "Add clear retention duration and deletion policy to satisfy storage limitation requirements.",
    },
    {
        "rule_id": "hipaa_phi_present",
        "regulation": "hipaa",
        "title": "Potential PHI detected",
        "pattern": re.compile(r"\b(medical record|diagnosis|treatment plan|patient id|insurance id|mrn)\b", re.IGNORECASE),
        "severity": "high",
        "recommendation": "Ensure HIPAA minimum necessary controls, access logging, and BAA-covered handling are in place.",
    },
    {
        "rule_id": "hipaa_no_safeguard_clause",
        "regulation": "hipaa",
        "title": "Safeguard controls not referenced",
        "pattern": re.compile(r"\b(encryption at rest|audit log|access control|least privilege|breach notification)\b", re.IGNORECASE),
        "severity": "medium",
        "invert": True,
        "recommendation": "Add administrative, technical, and physical safeguard commitments for PHI workflows.",
    },
    {
        "rule_id": "ccpa_sale_or_share_language",
        "regulation": "ccpa",
        "title": "Data sale/share language detected",
        "pattern": re.compile(
            r"\b(sell\s+(your\s+)?personal\s+information|sale\s+of\s+personal\s+information|share\s+personal\s+information|targeted\s+advertising|cross-context\s+behavioral\s+advertising|third-party\s+advertising)\b",
            re.IGNORECASE,
        ),
        "severity": "high",
        "recommendation": "Add opt-out mechanisms and clear notice for sale/share handling under CCPA/CPRA.",
    },
    {
        "rule_id": "ccpa_no_consumer_request_process",
        "regulation": "ccpa",
        "title": "Consumer request workflow not referenced",
        "pattern": re.compile(r"\b(access request|delete request|do not sell|privacy request|opt-out request|privacy intake)\b", re.IGNORECASE),
        "severity": "medium",
        "invert": True,
        "recommendation": "Define verified consumer request intake and response SLA for disclosure/deletion requests.",
    },
    {
        "rule_id": "soc2_no_change_control",
        "regulation": "soc2",
        "title": "Change control language missing",
        "pattern": re.compile(r"\b(change management|change control|approval workflow|deployment review)\b", re.IGNORECASE),
        "severity": "medium",
        "invert": True,
        "recommendation": "Include documented change control and approval evidence for SOC 2 operational integrity.",
    },
    {
        "rule_id": "soc2_no_incident_response",
        "regulation": "soc2",
        "title": "Incident response process missing",
        "pattern": re.compile(r"\b(incident response|security incident|postmortem|containment)\b", re.IGNORECASE),
        "severity": "medium",
        "invert": True,
        "recommendation": "Add incident response, escalation, and post-incident review commitments.",
    },
    {
        "rule_id": "ada_accessibility_obligation_missing",
        "regulation": "ada",
        "title": "Accessibility commitment not stated",
        "pattern": re.compile(r"\b(WCAG|accessibility|screen reader|keyboard navigation|reasonable accommodation)\b", re.IGNORECASE),
        "severity": "medium",
        "invert": True,
        "recommendation": "Add ADA/WCAG accessibility obligations and remediation SLAs for user-facing services.",
    },
]

DEFAULT_REGULATIONS = ["gdpr", "hipaa", "ccpa", "soc2", "ada"]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = max(100_000, MAX_REQUEST_BYTES)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                checks_used_this_month INTEGER NOT NULL DEFAULT 0,
                month_reset TEXT,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS compliance_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT NOT NULL,
                request_id TEXT NOT NULL,
                regulation_count INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                flag_count INTEGER NOT NULL,
                content_type TEXT,
                plan TEXT NOT NULL DEFAULT 'free',
                char_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stripe_session_id TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(stripe_session_id, notification_type)
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS sales_leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                plan TEXT NOT NULL,
                source TEXT,
                utm_source TEXT,
                utm_medium TEXT,
                utm_campaign TEXT,
                utm_content TEXT,
                utm_term TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_sales_leads_created ON sales_leads(created_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_sales_leads_email ON sales_leads(email)")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT NOT NULL,
                period_key TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(api_key, period_key, alert_type)
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limits (
                scope TEXT NOT NULL,
                bucket TEXT NOT NULL,
                window_start INTEGER NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (scope, bucket, window_start)
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_compliance_checks_created_at ON compliance_checks(created_at)")

        cols = {row[1] for row in c.execute("PRAGMA table_info(compliance_checks)").fetchall()}
        if "plan" not in cols:
            c.execute("ALTER TABLE compliance_checks ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'")
        if "char_count" not in cols:
            c.execute("ALTER TABLE compliance_checks ADD COLUMN char_count INTEGER NOT NULL DEFAULT 0")


def parse_allowed_origins() -> set[str]:
    allowed: set[str] = set()
    if CORS_ALLOW_ORIGINS_RAW:
        for part in CORS_ALLOW_ORIGINS_RAW.split(","):
            origin = part.strip()
            if origin:
                allowed.add(origin.rstrip("/"))
    if PUBLIC_BASE_URL:
        parsed = urllib.parse.urlparse(PUBLIC_BASE_URL)
        if parsed.scheme and parsed.netloc:
            allowed.add(f"{parsed.scheme}://{parsed.netloc}")
    return allowed


ALLOWED_ORIGINS = parse_allowed_origins()


def origin_allowed(origin: str | None) -> bool:
    if not origin:
        return False
    return origin.rstrip("/") in ALLOWED_ORIGINS


def client_ip() -> str:
    for header in ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
        raw = request.headers.get(header, "").strip()
        if not raw:
            continue
        if header == "X-Forwarded-For":
            return raw.split(",")[0].strip()
        return raw
    return (request.remote_addr or "unknown").strip() or "unknown"


def bucketize(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def check_rate_limit(scope: str, bucket: str, limit: int, window_seconds: int | None = None) -> tuple[bool, int]:
    if limit <= 0:
        return True, 0
    window = max(1, window_seconds or RATE_LIMIT_WINDOW_SECONDS)
    now_ts = int(datetime.now(timezone.utc).timestamp())
    start = now_ts - (now_ts % window)
    retry_after = max(1, window - (now_ts - start))
    now = now_iso()

    with conn() as c:
        c.execute(
            """
            INSERT INTO rate_limits (scope, bucket, window_start, count, updated_at)
            VALUES (?, ?, ?, 1, ?)
            ON CONFLICT(scope, bucket, window_start)
            DO UPDATE SET count = count + 1, updated_at = excluded.updated_at
            """,
            (scope, bucket, start, now),
        )
        row = c.execute(
            """
            SELECT count FROM rate_limits
            WHERE scope = ? AND bucket = ? AND window_start = ?
            """,
            (scope, bucket, start),
        ).fetchone()
        if now_ts % 23 == 0:
            c.execute("DELETE FROM rate_limits WHERE window_start < ?", (start - (window * 10),))

    current = int(row["count"]) if row else 1
    return current <= limit, retry_after


def parse_payload() -> dict[str, Any]:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise ValueError("Invalid JSON body")
    return payload


def external_base_url() -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/")
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    return f"{proto}://{host}".rstrip("/")


def clean_text(value: Any, max_len: int = 120000) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) > max_len:
        return text[:max_len]
    return text


def blocked_checkout_email_reason(email: str) -> str:
    normalized = clean_text(email, max_len=255).lower()
    if not EMAIL_RE.match(normalized):
        return "Valid email required"
    local, _, domain = normalized.partition("@")
    if not local or not domain:
        return "Valid email required"
    if domain in BLOCKED_CHECKOUT_EMAIL_DOMAINS or domain.endswith(".invalid"):
        return "Use a real work email to continue"
    if any(token in local for token in BLOCKED_CHECKOUT_LOCAL_TOKENS):
        return "Test/disposable emails are blocked"
    return ""


def month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def day_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def checks_today(plan: str | None = None) -> int:
    prefix = day_key() + "%"
    with conn() as c:
        if plan:
            row = c.execute(
                """
                SELECT COUNT(1) AS total
                FROM compliance_checks
                WHERE created_at LIKE ? AND plan = ?
                """,
                (prefix, plan),
            ).fetchone()
        else:
            row = c.execute(
                """
                SELECT COUNT(1) AS total
                FROM compliance_checks
                WHERE created_at LIKE ?
                """,
                (prefix,),
            ).fetchone()
    return int(row["total"]) if row else 0


def get_key_record(api_key: str) -> dict[str, Any] | None:
    with conn() as c:
        row = c.execute("SELECT * FROM api_keys WHERE api_key = ?", (api_key,)).fetchone()
    return dict(row) if row else None


def get_key_record_by_email(email: str) -> dict[str, Any] | None:
    normalized = clean_text(email, max_len=255).lower()
    if not EMAIL_RE.match(normalized):
        return None
    with conn() as c:
        row = c.execute("SELECT * FROM api_keys WHERE email = ? ORDER BY id DESC LIMIT 1", (normalized,)).fetchone()
    return dict(row) if row else None


def create_api_key(email: str, plan: str = "free") -> str:
    key = "ck_" + secrets.token_hex(24)
    now = now_iso()
    with conn() as c:
        c.execute(
            """
            INSERT INTO api_keys (api_key, email, plan, checks_used_this_month, month_reset, created_at, updated_at)
            VALUES (?, ?, ?, 0, ?, ?, ?)
            """,
            (key, email.lower(), plan, month_key(), now, now),
        )
    return key


def reset_usage_if_needed(api_key: str) -> dict[str, Any] | None:
    record = get_key_record(api_key)
    if not record:
        return None
    current = month_key()
    if record.get("month_reset") != current:
        now = now_iso()
        with conn() as c:
            c.execute(
                """
                UPDATE api_keys
                SET checks_used_this_month = 0, month_reset = ?, updated_at = ?
                WHERE api_key = ?
                """,
                (current, now, api_key),
            )
        record = get_key_record(api_key)
    return record


def mark_notification_sent(session_id: str, notif_type: str) -> bool:
    try:
        with conn() as c:
            c.execute(
                """
                INSERT INTO billing_notifications (stripe_session_id, notification_type, created_at)
                VALUES (?, ?, ?)
                """,
                (session_id, notif_type, now_iso()),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def send_followup_email(to_email: str, subject: str, html_body: str) -> bool:
    if not RESEND_API_KEY or not to_email:
        return False
    data = json.dumps(
        {
            "from": FOLLOWUP_FROM_EMAIL,
            "to": [to_email],
            "subject": subject,
            "html": html_body,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=data,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= getattr(resp, "status", 0) < 300
    except (urllib.error.URLError, urllib.error.HTTPError):
        return False


def payment_link_for_plan(plan: str) -> str:
    mapping = {
        "setup": SETUP_PAYMENT_LINK,
        "starter": STARTER_PAYMENT_LINK,
        "pro": PRO_PAYMENT_LINK,
        "scale": SCALE_PAYMENT_LINK,
    }
    return mapping.get(plan, "")


def plan_checkout_url(plan: str) -> str:
    if (
        stripe
        and STRIPE_SECRET_KEY
        and SELF_SERVE_CHECKOUT_ENABLED
        and STRIPE_PRICE_IDS.get(plan)
        and plan in {"starter", "pro", "scale"}
    ):
        return f"{external_base_url()}/api/checkout/start?plan={urllib.parse.quote(plan)}"
    return payment_link_for_plan(plan)


def infer_plan_from_checkout_session(session_obj: dict[str, Any]) -> str:
    metadata_plan = (clean_text((session_obj.get("metadata") or {}).get("plan"), max_len=20) or "").lower()
    if metadata_plan in STRIPE_PRICE_IDS:
        return metadata_plan

    price_to_plan = {v: k for k, v in STRIPE_PRICE_IDS.items() if v}
    line_items = ((session_obj.get("line_items") or {}).get("data") or [])
    for item in line_items:
        price_id = ((item or {}).get("price") or {}).get("id")
        mapped = price_to_plan.get(price_id)
        if mapped:
            return mapped

    session_id = clean_text(session_obj.get("id"), max_len=255)
    if session_id and stripe and STRIPE_SECRET_KEY:
        try:
            expanded = stripe.checkout.Session.retrieve(session_id, expand=["line_items.data.price"])
            for item in ((expanded.get("line_items") or {}).get("data") or []):
                price_id = ((item or {}).get("price") or {}).get("id")
                mapped = price_to_plan.get(price_id)
                if mapped:
                    return mapped
        except Exception:
            pass

    return "starter"


def checkout_link_with_prefilled_email(base_link: str, email: str) -> str:
    if not base_link or not email:
        return base_link
    try:
        parts = urllib.parse.urlsplit(base_link)
        q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        q.append(("prefilled_email", email))
        query = urllib.parse.urlencode(q)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))
    except Exception:
        return base_link


def record_sales_lead(email: str, plan: str, source: str, utm: dict[str, str]) -> None:
    with conn() as c:
        c.execute(
            """
            INSERT INTO sales_leads (
                email, plan, source, utm_source, utm_medium, utm_campaign, utm_content, utm_term, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                plan,
                source,
                utm.get("utm_source", ""),
                utm.get("utm_medium", ""),
                utm.get("utm_campaign", ""),
                utm.get("utm_content", ""),
                utm.get("utm_term", ""),
                now_iso(),
            ),
        )


def runtime_error_response(err: RuntimeError) -> Response:
    msg = str(err)
    if msg.startswith("rate_limit_exceeded:"):
        retry_after = msg.split(":", 1)[1].strip() or "60"
        resp = jsonify({"detail": "rate_limit_exceeded"})
        resp.status_code = 429
        resp.headers["Retry-After"] = retry_after
        return resp
    if msg == "free_tier_capacity_reached":
        resp = jsonify(
            {
                "detail": "free_tier_capacity_reached",
                "upgrade_url": plan_checkout_url("starter"),
                "message": "Free-tier daily capacity is full. Upgrade for priority access.",
            }
        )
        resp.status_code = 429
        return resp
    if msg == "service_capacity_reached":
        resp = jsonify({"detail": "service_capacity_reached", "message": "Service is at daily capacity. Try again shortly."})
        resp.status_code = 503
        return resp
    resp = jsonify({"detail": msg})
    resp.status_code = 429
    return resp


def require_api_key() -> dict[str, Any]:
    ip = client_ip()
    ip_ok, ip_retry = check_rate_limit("api_ip", bucketize(ip), API_RATE_LIMIT_PER_IP_PER_MINUTE)
    if not ip_ok:
        raise RuntimeError(f"rate_limit_exceeded:{ip_retry}")

    auth = request.headers.get("Authorization", "")
    x_api_key = request.headers.get("X-API-Key", "")
    api_key = ""

    if auth.startswith("Bearer "):
        api_key = auth[7:].strip()
    elif x_api_key:
        api_key = x_api_key.strip()

    if not api_key:
        raise PermissionError("API key required")
    if not API_KEY_RE.match(api_key):
        raise PermissionError("Invalid API key")

    key_ok, key_retry = check_rate_limit("api_key", bucketize(api_key), API_RATE_LIMIT_PER_KEY_PER_MINUTE)
    if not key_ok:
        raise RuntimeError(f"rate_limit_exceeded:{key_retry}")

    record = reset_usage_if_needed(api_key)
    if not record:
        raise PermissionError("Invalid API key")

    plan = str(record.get("plan", "free")).lower()

    if GLOBAL_DAILY_CHECK_CAP > 0:
        if checks_today() >= GLOBAL_DAILY_CHECK_CAP:
            raise RuntimeError("service_capacity_reached")
    if plan == "free" and FREE_TIER_DAILY_CHECK_CAP > 0:
        if checks_today("free") >= FREE_TIER_DAILY_CHECK_CAP:
            raise RuntimeError("free_tier_capacity_reached")

    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    used = int(record.get("checks_used_this_month", 0))

    if used >= limits["checks_per_month"]:
        raise RuntimeError("monthly_limit_exceeded")

    return record


def increment_usage(api_key: str, delta: int = 1) -> int:
    with conn() as c:
        c.execute(
            """
            UPDATE api_keys
            SET checks_used_this_month = checks_used_this_month + ?, updated_at = ?
            WHERE api_key = ?
            """,
            (max(1, delta), now_iso(), api_key),
        )
        row = c.execute(
            "SELECT checks_used_this_month FROM api_keys WHERE api_key = ?",
            (api_key,),
        ).fetchone()
    return int(row["checks_used_this_month"]) if row else 0


def evidence_snippet(text: str, start: int, end: int, window: int = 60) -> str:
    left = max(0, start - window)
    right = min(len(text), end + window)
    return text[left:right].strip()


def resolve_regulations(regulations: Any) -> list[str]:
    if not regulations:
        return DEFAULT_REGULATIONS
    if isinstance(regulations, str):
        parts = [p.strip().lower() for p in regulations.split(",") if p.strip()]
        return [p for p in parts if p in DEFAULT_REGULATIONS] or DEFAULT_REGULATIONS
    if isinstance(regulations, list):
        cleaned = [str(item).strip().lower() for item in regulations if str(item).strip()]
        return [p for p in cleaned if p in DEFAULT_REGULATIONS] or DEFAULT_REGULATIONS
    return DEFAULT_REGULATIONS


def classify_severity(score: int, has_critical: bool, has_high: bool) -> str:
    if has_critical:
        return "critical"
    if has_high:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def evaluate_compliance(text: str, regulations: list[str], content_type: str | None = None) -> dict[str, Any]:
    flags: list[dict[str, Any]] = []

    for rule in RULES:
        reg = rule["regulation"]
        if reg not in regulations:
            continue

        pattern: re.Pattern[str] = rule["pattern"]
        invert = bool(rule.get("invert", False))
        match = pattern.search(text)

        should_flag = (match is None) if invert else (match is not None)
        if not should_flag:
            continue

        if match is not None:
            snippet = evidence_snippet(text, match.start(), match.end())
        else:
            snippet = "No matching safeguard language detected in supplied content."

        flags.append(
            {
                "rule_id": rule["rule_id"],
                "regulation": reg,
                "title": rule["title"],
                "severity": rule["severity"],
                "evidence": snippet,
                "recommendation": rule["recommendation"],
            }
        )

    total_score = min(100, sum(SEVERITY_WEIGHT.get(flag["severity"], 8) for flag in flags))
    has_critical = any(flag["severity"] == "critical" for flag in flags)
    has_high = any(flag["severity"] == "high" for flag in flags)
    severity = classify_severity(total_score, has_critical, has_high)
    passed = not has_critical and not has_high and total_score < 30

    by_regulation: dict[str, dict[str, Any]] = {}
    for reg in regulations:
        reg_flags = [flag for flag in flags if flag["regulation"] == reg]
        reg_score = min(100, sum(SEVERITY_WEIGHT.get(flag["severity"], 8) for flag in reg_flags))
        by_regulation[reg] = {
            "risk_score": reg_score,
            "flag_count": len(reg_flags),
            "status": "pass" if reg_score < 30 else "review",
        }

    return {
        "pass": passed,
        "risk_score": total_score,
        "severity": severity,
        "content_type": content_type or "text",
        "flag_count": len(flags),
        "flags": flags,
        "regulation_summary": by_regulation,
        "checked_at": now_iso(),
    }


def maybe_send_upgrade_alert(key_record: dict[str, Any], used: int) -> None:
    plan = str(key_record.get("plan", "free")).lower()
    if plan != "free":
        return
    limit = PLAN_LIMITS["free"]["checks_per_month"]
    pct = (used * 100) / max(1, limit)
    alert_type = ""
    if pct >= 95:
        alert_type = "usage_95"
    elif pct >= 80:
        alert_type = "usage_80"
    else:
        return

    api_key = str(key_record.get("api_key", ""))
    if not api_key:
        return
    period = month_key()
    try:
        with conn() as c:
            c.execute(
                """
                INSERT INTO usage_alerts (api_key, period_key, alert_type, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (api_key, period, alert_type, now_iso()),
            )
    except sqlite3.IntegrityError:
        return

    email = str(key_record.get("email", "")).strip().lower()
    remaining = max(0, limit - used)
    if email:
        send_followup_email(
            email,
            "CheckAPI usage limit warning",
            (
                f"<p>You have used <b>{used}/{limit}</b> free checks this month.</p>"
                f"<p>Remaining: <b>{remaining}</b></p>"
                f"<p>Upgrade now: <a href=\"{plan_checkout_url('starter')}\">Start Starter</a></p>"
            ),
        )
    if FOLLOWUP_INBOX_EMAIL:
        send_followup_email(
            FOLLOWUP_INBOX_EMAIL,
            "CheckAPI high-intent free user",
            (
                f"<p><b>Email:</b> {email or 'n/a'}</p>"
                f"<p><b>Usage:</b> {used}/{limit} ({int(pct)}%)</p>"
                f"<p><b>Upgrade link:</b> <a href=\"{plan_checkout_url('starter')}\">{plan_checkout_url('starter')}</a></p>"
            ),
        )


def record_check(
    api_key: str,
    request_id: str,
    result: dict[str, Any],
    regulation_count: int,
    content_type: str,
    plan: str,
    char_count: int,
) -> None:
    with conn() as c:
        c.execute(
            """
            INSERT INTO compliance_checks
            (api_key, request_id, regulation_count, risk_score, severity, flag_count, content_type, plan, char_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                api_key,
                request_id,
                regulation_count,
                int(result.get("risk_score", 0)),
                str(result.get("severity", "none")),
                int(result.get("flag_count", 0)),
                content_type,
                plan,
                max(0, char_count),
                now_iso(),
            ),
        )


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "check_compliance",
            "description": "Validates text/contracts/documents against GDPR, HIPAA, SOC2, CCPA, ADA and returns pass/fail, risk score, flags, and remediation. MUST run before finalizing compliance-sensitive output.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to validate for compliance risk"},
                    "regulations": {
                        "type": ["array", "string"],
                        "description": "Subset of regulations to check: gdpr, hipaa, ccpa, soc2, ada",
                    },
                    "content_type": {"type": "string", "description": "contract, policy, output, email, chat"},
                },
                "required": ["text"],
            },
        },
        {
            "name": "check_batch_compliance",
            "description": "Batch validate multiple outputs/documents and return per-item pass/fail and risk results.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "text": {"type": "string"},
                                "id": {"type": "string"},
                                "content_type": {"type": "string"},
                            },
                            "required": ["text"],
                        },
                    },
                    "regulations": {"type": ["array", "string"]},
                },
                "required": ["items"],
            },
        },
        {
            "name": "compliance_usage_status",
            "description": "Returns current API key plan, checks used, and checks remaining this month.",
            "input_schema": {"type": "object", "properties": {}},
        },
    ]


def run_single_check(payload: dict[str, Any], key_record: dict[str, Any], *, count_usage: bool = True) -> dict[str, Any]:
    text = clean_text(payload.get("text"), max_len=MAX_TEXT_CHARS_GLOBAL)
    if not text:
        raise ValueError("text is required")

    plan = str(key_record.get("plan", "free")).lower()
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    if len(text) > limits["max_chars"]:
        raise ValueError(f"text exceeds max_chars for {plan} plan")

    regulations = resolve_regulations(payload.get("regulations"))
    content_type = clean_text(payload.get("content_type"), max_len=100) or "text"

    result = evaluate_compliance(text, regulations, content_type)

    if count_usage:
        used_after = increment_usage(key_record["api_key"], 1)
        request_id = "chk_" + secrets.token_hex(8)
        record_check(
            key_record["api_key"],
            request_id,
            result,
            len(regulations),
            content_type,
            plan,
            len(text),
        )
        maybe_send_upgrade_alert(key_record, used_after)
        result["request_id"] = request_id

    return result


def render_landing(filename: str) -> str:
    page = LANDING_DIR / filename
    if not page.exists():
        return ""
    base = external_base_url()
    html = page.read_text(encoding="utf-8")
    return (
        html.replace("{{BASE_URL}}", base)
        .replace("{{DATAWEAVE_HOME_URL}}", DATAWEAVE_HOME_URL)
        .replace("{{EXTRACT_API_URL}}", EXTRACT_API_URL)
        .replace("{{REDACT_API_URL}}", REDACT_API_URL)
        .replace("{{AGENT_ROUTER_URL}}", AGENT_ROUTER_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_MONTHLY_URL}}", AGENT_ROUTER_BUNDLE_MONTHLY_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_FULL_URL}}", AGENT_ROUTER_BUNDLE_FULL_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_DASHBOARD_URL}}", AGENT_ROUTER_BUNDLE_DASHBOARD_URL)
        .replace("{{SETUP_PAYMENT_LINK}}", SETUP_PAYMENT_LINK)
        .replace("{{STARTER_PAYMENT_LINK}}", plan_checkout_url("starter"))
        .replace("{{PRO_PAYMENT_LINK}}", plan_checkout_url("pro"))
        .replace("{{SCALE_PAYMENT_LINK}}", plan_checkout_url("scale"))
    )


def dataweave_stack_payload(base: str) -> dict[str, Any]:
    return {
        "company": "DataWeaveAI company",
        "stack_name": "DataWeave Agent Stack",
        "message": "Fast path for agents: extract, redact, validate, then route to local service execution.",
        "recommended_order": ["extractapi", "redactapi", "checkapi", "agent-router"],
        "services": [
            {
                "id": "extractapi",
                "name": "ExtractAPI",
                "url": EXTRACT_API_URL,
                "purpose": "Schema-based document extraction into structured JSON.",
                "typical_use": "Turn PDFs/images into machine-usable fields.",
            },
            {
                "id": "redactapi",
                "name": "RedactAPI",
                "url": REDACT_API_URL,
                "purpose": "PII/PHI redaction before downstream actions.",
                "typical_use": "Mask sensitive data to reduce risk and compliance exposure.",
            },
            {
                "id": "checkapi",
                "name": "CheckAPI",
                "url": base,
                "purpose": "Compliance guardrail validation for outputs and docs.",
                "typical_use": "Return pass/fail, risk score, flags, and remediation before final response.",
            },
            {
                "id": "agent-router",
                "name": "Agent Router",
                "url": AGENT_ROUTER_URL,
                "purpose": "Intent routing and local service transaction middleware.",
                "typical_use": "Route qualified intents to providers and close service jobs.",
            },
        ],
        "discovery": {
            "checkapi_transport": f"{base}/mcp",
            "checkapi_openapi": f"{base}/openapi.json",
            "checkapi_docs": f"{base}/docs",
            "stack_manifest": f"{base}/v1/public/stack",
        },
        "bundle": {
            "monthly_usd": 656,
            "full_launch_due_today_usd": 3156,
            "monthly_checkout": AGENT_ROUTER_BUNDLE_MONTHLY_URL,
            "full_launch_checkout": AGENT_ROUTER_BUNDLE_FULL_URL,
            "dashboard": AGENT_ROUTER_BUNDLE_DASHBOARD_URL,
        },
    }


@app.before_request
def handle_preflight() -> Response | None:
    if request.method != "OPTIONS":
        return None
    resp = Response(status=204)
    return resp


@app.errorhandler(RequestEntityTooLarge)
def handle_payload_too_large(_: RequestEntityTooLarge) -> Response:
    return jsonify({"detail": "payload_too_large"}), 413


@app.after_request
def after_request(resp: Response):
    origin = request.headers.get("Origin")
    if origin_allowed(origin):
        resp.headers["Access-Control-Allow-Origin"] = origin.rstrip("/")
        resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-API-Key"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["X-XSS-Protection"] = "0"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    if resp.mimetype == "text/html":
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data: https:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self' https://buy.stripe.com"
        )
    return resp


@app.route("/health", methods=["GET"])
def health() -> Response:
    return jsonify(
        {
            "status": "ok",
            "service": "checkapi",
            "time": now_iso(),
            "payment_ready": not STARTER_PAYMENT_LINK.startswith("https://buy.stripe.com/replace"),
        }
    )


@app.route("/", methods=["GET"])
def home() -> Response:
    html = render_landing("index.html")
    if html:
        return Response(html, mimetype="text/html")
    return Response("<h1>CheckAPI</h1>", mimetype="text/html")


@app.route("/payment-success", methods=["GET"])
def payment_success_page() -> Response:
    session_id = clean_text(request.args.get("session_id"), max_len=255) or ""
    base = external_base_url()
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CheckAPI | Payment Confirmation</title>
  <meta name="description" content="Payment confirmation and activation steps for CheckAPI." />
  <style>
    body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #020a16; color: #e2e8f0; }}
    .wrap {{ max-width: 760px; margin: 24px auto; padding: 0 16px; }}
    .card {{ background: #08162a; border: 1px solid #123258; border-radius: 12px; padding: 24px; }}
    .status {{ font-weight: 700; margin: 8px 0 14px; color: #7dd3fc; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }}
    .btn {{ text-decoration: none; border-radius: 10px; padding: 10px 14px; font-weight: 700; display: inline-block; }}
    .btn-primary {{ background: #1fd3ff; color: #07203b; }}
    .btn-muted {{ border: 1px solid #1e4068; color: #d9efff; background: #0b1d34; }}
    input {{ width: 100%; max-width: 360px; margin-top: 8px; border: 1px solid #20456e; border-radius: 8px; background: #061427; color: #d9efff; padding: 10px; }}
    button {{ margin-top: 8px; border: 1px solid #20527f; background: #0b2947; color: #d9efff; border-radius: 8px; padding: 9px 12px; font-weight: 700; cursor: pointer; }}
    small {{ color: #9bb7d8; }}
    a {{ color: #54d1ff; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Payment Received. Activation In Progress.</h1>
      <p id="status-text" class="status">Verifying your Stripe session...</p>
      <p id="detail-text">Session: <code>{session_id or "missing"}</code></p>
      <p>After payment, your API key is sent to the checkout email automatically.</p>
      <div class="actions">
        <a class="btn btn-primary" href="/docs">Open Docs</a>
        <a class="btn btn-muted" href="/">Back to Home</a>
      </div>
      <hr style="border:0;border-top:1px solid #143456;margin:20px 0;" />
      <h3 style="margin:0 0 8px;">Did not receive your key email?</h3>
      <p><small>Use this to resend key + activation details.</small></p>
      <input type="email" id="recover-email" placeholder="you@company.com" />
      <br />
      <button type="button" id="recover-btn">Resend Access Email</button>
      <p id="recover-note"><small></small></p>
    </div>
  </div>
  <script>
    (function () {{
      const sessionId = {json.dumps(session_id)};
      const base = {json.dumps(base)};
      const statusEl = document.getElementById("status-text");
      const detailEl = document.getElementById("detail-text");
      const emailInput = document.getElementById("recover-email");
      const recoverBtn = document.getElementById("recover-btn");
      const recoverNote = document.getElementById("recover-note");

      async function verify(maxAttempts = 12) {{
        if (!sessionId) {{
          statusEl.textContent = "Missing session ID. Use your checkout success link or request access email resend below.";
          return;
        }}
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {{
          try {{
            const res = await fetch(`${{base}}/api/billing/verify-session?session_id=${{encodeURIComponent(sessionId)}}`, {{ cache: "no-store" }});
            const data = await res.json();
            if (data.verified) {{
              statusEl.textContent = `Payment confirmed for plan: ${{data.plan || "starter"}}`;
              const email = data.email || "";
              if (email) {{
                detailEl.textContent = `Activation email sent to: ${{email}}`;
                emailInput.value = email;
              }} else {{
                detailEl.textContent = "Payment confirmed. API key email will be sent to checkout email.";
              }}
              return;
            }}
            statusEl.textContent = `Payment pending... auto-check ${{attempt}}/${{maxAttempts}}`;
            detailEl.textContent = data.reason ? `Status: ${{data.reason}}` : "Waiting for Stripe confirmation.";
          }} catch (err) {{
            statusEl.textContent = "Unable to verify payment right now. You can still request key resend below.";
            return;
          }}
          await new Promise((resolve) => setTimeout(resolve, 5000));
        }}
        statusEl.textContent = "Payment not confirmed yet. Refresh in 30 seconds.";
      }}

      recoverBtn.addEventListener("click", async () => {{
        const email = (emailInput.value || "").trim();
        if (!email || !email.includes("@")) {{
          recoverNote.innerHTML = "<small>Enter a valid email first.</small>";
          return;
        }}
        recoverBtn.disabled = true;
        recoverNote.innerHTML = "<small>Sending...</small>";
        try {{
          await fetch(`${{base}}/api/access/resend-key`, {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ email }})
          }});
          recoverNote.innerHTML = "<small>If this email exists, access details were sent.</small>";
        }} catch (_) {{
          recoverNote.innerHTML = "<small>Unable to send right now. Try again in a minute.</small>";
        }} finally {{
          recoverBtn.disabled = false;
        }}
      }});

      verify();
    }})();
  </script>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@app.route("/docs", methods=["GET"])
def docs_page() -> Response:
    html = render_landing("docs.html")
    if html:
        return Response(html, mimetype="text/html")
    return jsonify({"openapi": external_base_url() + "/openapi.json"})


@app.route("/privacy", methods=["GET"])
def privacy_page() -> Response:
    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Privacy Policy | CheckAPI</title>
  <style>
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #020a16; color: #e2e8f0; }
    .wrap { max-width: 820px; margin: 0 auto; padding: 24px 16px 40px; }
    .card { background: #08162a; border: 1px solid #123258; border-radius: 12px; padding: 24px; }
    a { color: #52d0ff; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Privacy Policy</h1>
      <p>CheckAPI processes submitted text and documents to score compliance risk and produce remediation guidance.</p>
      <p>We use trusted processors for hosting, payments, and notifications. We do not sell personal data.</p>
      <p>Contact: joseph@dataweaveai.com</p>
      <p><a href="/">Back to CheckAPI</a></p>
      <p style="font-size:12px;color:#93c5fd;">CheckAPI is a DataWeaveAI company.</p>
    </div>
  </div>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@app.route("/terms", methods=["GET"])
def terms_page() -> Response:
    html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Terms of Service | CheckAPI</title>
  <style>
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #020a16; color: #e2e8f0; }
    .wrap { max-width: 820px; margin: 0 auto; padding: 24px 16px 40px; }
    .card { background: #08162a; border: 1px solid #123258; border-radius: 12px; padding: 24px; }
    a { color: #52d0ff; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Terms of Service</h1>
      <p>By using CheckAPI, you agree to these terms of service.</p>
      <p>You are responsible for lawful handling of content and final policy decisions based on returned risk outputs.</p>
      <p>Paid plans and setup services follow Stripe checkout terms and renewal settings.</p>
      <p>Contact: joseph@dataweaveai.com</p>
      <p><a href="/">Back to CheckAPI</a></p>
      <p style="font-size:12px;color:#93c5fd;">CheckAPI is a DataWeaveAI company.</p>
    </div>
  </div>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@app.route("/openapi.json", methods=["GET"])
def openapi_spec() -> Response:
    base = external_base_url()
    spec = {
        "openapi": "3.1.0",
        "info": {
            "title": "CheckAPI",
            "version": "1.0.0",
            "description": "Agent-native compliance guardrail API for GDPR, HIPAA, CCPA, SOC2, and ADA validation.",
        },
        "servers": [{"url": base}],
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer"},
                "ApiKeyHeader": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            },
            "schemas": {
                "SignupRequest": {
                    "type": "object",
                    "properties": {"email": {"type": "string", "format": "email"}},
                    "required": ["email"],
                },
                "SignupResponse": {
                    "type": "object",
                    "properties": {
                        "api_key": {"type": "string"},
                        "plan": {"type": "string"},
                        "checks_per_month": {"type": "integer"},
                        "status": {"type": "string"},
                        "message": {"type": "string"},
                    },
                },
                "LeadRequest": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string", "format": "email"},
                        "plan": {"type": "string", "enum": ["setup", "starter", "pro", "scale"]},
                        "source": {"type": "string"},
                        "utm_source": {"type": "string"},
                        "utm_medium": {"type": "string"},
                        "utm_campaign": {"type": "string"},
                        "utm_content": {"type": "string"},
                        "utm_term": {"type": "string"},
                    },
                    "required": ["email", "plan"],
                },
                "LeadResponse": {
                    "type": "object",
                    "properties": {
                        "checkout_url": {"type": "string"},
                        "plan": {"type": "string"},
                        "captured": {"type": "boolean"},
                    },
                },
                "StackResponse": {
                    "type": "object",
                    "properties": {
                        "company": {"type": "string"},
                        "stack_name": {"type": "string"},
                        "message": {"type": "string"},
                        "recommended_order": {"type": "array", "items": {"type": "string"}},
                        "services": {"type": "array", "items": {"type": "object"}},
                        "discovery": {"type": "object"},
                    },
                },
                "CheckRequest": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to validate"},
                        "regulations": {
                            "oneOf": [
                                {"type": "array", "items": {"type": "string"}},
                                {"type": "string"},
                            ]
                        },
                        "content_type": {"type": "string", "description": "contract, policy, output, email, chat"},
                    },
                    "required": ["text"],
                },
                "CheckFlag": {
                    "type": "object",
                    "properties": {
                        "rule_id": {"type": "string"},
                        "regulation": {"type": "string"},
                        "title": {"type": "string"},
                        "severity": {"type": "string"},
                        "evidence": {"type": "string"},
                        "recommendation": {"type": "string"},
                    },
                },
                "CheckResult": {
                    "type": "object",
                    "properties": {
                        "pass": {"type": "boolean"},
                        "risk_score": {"type": "integer"},
                        "severity": {"type": "string"},
                        "content_type": {"type": "string"},
                        "flag_count": {"type": "integer"},
                        "flags": {"type": "array", "items": {"$ref": "#/components/schemas/CheckFlag"}},
                        "regulation_summary": {"type": "object"},
                        "checked_at": {"type": "string"},
                        "request_id": {"type": "string"},
                    },
                },
                "BatchItem": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "text": {"type": "string"},
                        "content_type": {"type": "string"},
                    },
                    "required": ["text"],
                },
                "BatchRequest": {
                    "type": "object",
                    "properties": {
                        "items": {"type": "array", "items": {"$ref": "#/components/schemas/BatchItem"}},
                        "regulations": {
                            "oneOf": [
                                {"type": "array", "items": {"type": "string"}},
                                {"type": "string"},
                            ]
                        },
                    },
                    "required": ["items"],
                },
                "BatchResponse": {
                    "type": "object",
                    "properties": {
                        "total": {"type": "integer"},
                        "successful": {"type": "integer"},
                        "results": {"type": "array", "items": {"type": "object"}},
                    },
                },
                "UsageResponse": {
                    "type": "object",
                    "properties": {
                        "plan": {"type": "string"},
                        "checks_used_this_month": {"type": "integer"},
                        "checks_limit": {"type": "integer"},
                        "checks_remaining": {"type": "integer"},
                        "usage_percent": {"type": "integer"},
                        "max_chars": {"type": "integer"},
                        "batch_limit": {"type": "integer"},
                        "billing_period": {"type": "string"},
                        "upgrade_recommended": {"type": "boolean"},
                        "upgrade_url": {"type": "string"},
                    },
                },
                "MCPToolsResponse": {
                    "type": "object",
                    "properties": {
                        "tools": {"type": "array", "items": {"type": "object"}},
                    },
                },
                "MCPRequest": {
                    "type": "object",
                    "properties": {
                        "jsonrpc": {"type": "string"},
                        "id": {},
                        "method": {"type": "string", "description": "tools/list or tools/call"},
                        "params": {"type": "object"},
                    },
                    "required": ["method"],
                },
                "ErrorResponse": {
                    "type": "object",
                    "properties": {"detail": {"type": "string"}},
                },
            },
        },
        "paths": {
            "/api/signup": {
                "post": {
                    "summary": "Request API access (paid self-serve)",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/SignupRequest"},
                                "example": {"email": "agent-builder@company.com"},
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "API key created or returned",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SignupResponse"}}},
                        },
                        "400": {
                            "description": "Invalid input",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                    },
                }
            },
            "/api/public/lead": {
                "post": {
                    "summary": "Capture lead and return plan checkout URL",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LeadRequest"},
                                "example": {
                                    "email": "agent-builder@company.com",
                                    "plan": "starter",
                                    "source": "homepage_quick_checkout",
                                },
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Lead captured and checkout URL returned",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/LeadResponse"}}},
                        },
                        "400": {
                            "description": "Invalid input",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                        "429": {
                            "description": "Rate limited",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                    },
                }
            },
            "/v1/public/stack": {
                "get": {
                    "summary": "DataWeave unified 4-service agent stack manifest",
                    "responses": {
                        "200": {
                            "description": "Stack manifest for agents/orchestrators",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/StackResponse"}}},
                        }
                    },
                }
            },
            "/v1/check": {
                "post": {
                    "summary": "Single compliance validation",
                    "security": [{"BearerAuth": []}, {"ApiKeyHeader": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CheckRequest"},
                                "example": {
                                    "text": "We process health data and biometric data.",
                                    "regulations": ["gdpr", "hipaa"],
                                    "content_type": "contract",
                                },
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Validation result",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CheckResult"}}},
                        },
                        "400": {
                            "description": "Invalid input",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                        "401": {
                            "description": "Missing or invalid API key",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                        "429": {
                            "description": "Monthly quota exceeded",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                    },
                }
            },
            "/v1/batch": {
                "post": {
                    "summary": "Batch compliance validation",
                    "security": [{"BearerAuth": []}, {"ApiKeyHeader": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/BatchRequest"},
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Batch validation result",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/BatchResponse"}}},
                        },
                        "400": {
                            "description": "Invalid input",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                        "401": {
                            "description": "Missing or invalid API key",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                        "429": {
                            "description": "Monthly quota exceeded",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                    },
                }
            },
            "/v1/usage": {
                "get": {
                    "summary": "Usage and plan status",
                    "security": [{"BearerAuth": []}, {"ApiKeyHeader": []}],
                    "responses": {
                        "200": {
                            "description": "Usage info",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/UsageResponse"}}},
                        },
                        "401": {
                            "description": "Missing or invalid API key",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}},
                        },
                    },
                }
            },
            "/v1/mcp/tools": {
                "get": {
                    "summary": "Tool catalog for MCP agents",
                    "responses": {
                        "200": {
                            "description": "Tool catalog",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/MCPToolsResponse"}}},
                        }
                    },
                }
            },
            "/mcp": {
                "post": {
                    "summary": "MCP JSON-RPC transport endpoint",
                    "security": [{"BearerAuth": []}, {"ApiKeyHeader": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/MCPRequest"},
                                "examples": {
                                    "tools_list": {"value": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}},
                                    "tools_call": {
                                        "value": {
                                            "jsonrpc": "2.0",
                                            "id": 2,
                                            "method": "tools/call",
                                            "params": {
                                                "name": "check_compliance",
                                                "arguments": {"text": "Generated response body", "regulations": ["gdpr", "soc2"]},
                                            },
                                        }
                                    },
                                },
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "JSON-RPC response"},
                        "401": {"description": "Missing or invalid API key"},
                        "429": {"description": "Monthly quota exceeded"},
                    },
                }
            },
        },
    }
    return jsonify(spec)


@app.route("/api/signup", methods=["POST"])
def signup() -> Response:
    try:
        ip = client_ip()
        ip_ok, ip_retry = check_rate_limit("signup_ip", bucketize(ip), SIGNUP_RATE_LIMIT_PER_MINUTE)
        if not ip_ok:
            raise RuntimeError(f"rate_limit_exceeded:{ip_retry}")
        ip_daily_ok, ip_daily_retry = check_rate_limit("signup_ip_day", bucketize(ip), FREE_SIGNUPS_PER_IP_PER_DAY, 86400)
        if not ip_daily_ok:
            raise RuntimeError(f"rate_limit_exceeded:{ip_daily_retry}")

        payload = parse_payload()
        email = clean_text(payload.get("email"), max_len=255).lower()
        if not EMAIL_RE.match(email):
            return jsonify({"detail": "Valid email required"}), 400
        email_ok, email_retry = check_rate_limit("signup_email", bucketize(email), max(3, SIGNUP_RATE_LIMIT_PER_MINUTE))
        if not email_ok:
            raise RuntimeError(f"rate_limit_exceeded:{email_retry}")

        with conn() as c:
            existing = c.execute("SELECT api_key, plan FROM api_keys WHERE email = ?", (email,)).fetchone()

        if existing:
            if RESEND_API_KEY:
                send_followup_email(
                    email,
                    "Your CheckAPI key",
                    (
                        f"<h2>CheckAPI Access</h2>"
                        f"<p>API key: <code>{existing['api_key']}</code></p>"
                        f"<p>Current plan: {existing['plan']}</p>"
                        f"<p>Use Authorization header: <code>Bearer YOUR_API_KEY</code></p>"
                    ),
                )
            return jsonify(
                {
                    "status": "accepted",
                    "message": "If this email is registered, API key details have been sent to its inbox.",
                }
            )

        if not FREE_SIGNUP_ENABLED:
            return (
                jsonify(
                    {
                        "detail": "Free signup is disabled. Start Starter/Pro/Scale checkout from /#pricing.",
                    }
                ),
                410,
            )

        api_key = create_api_key(email, "free")

        send_followup_email(
            email,
            "Your CheckAPI key is ready",
            (
                f"<h2>CheckAPI Free Tier Enabled</h2>"
                f"<p>API key: <code>{api_key}</code></p>"
                f"<p>Free plan includes 500 checks/month.</p>"
                f"<p>Upgrade: <a href=\"{plan_checkout_url('starter')}\">Starter</a></p>"
            ),
        )

        if FOLLOWUP_INBOX_EMAIL:
            send_followup_email(
                FOLLOWUP_INBOX_EMAIL,
                "CheckAPI signup",
                f"<p><b>Email:</b> {email}</p><p><b>Plan:</b> free</p>",
            )

        if SIGNUP_EXPOSE_API_KEY_ON_CREATE:
            return jsonify({"api_key": api_key, "plan": "free", "checks_per_month": 500})
        return jsonify(
            {
                "status": "accepted",
                "message": "API key created. Check your inbox for the key.",
            }
        )
    except ValueError as e:
        return jsonify({"detail": str(e)}), 400
    except RuntimeError as e:
        return runtime_error_response(e)


@app.route("/v1/usage", methods=["GET"])
def usage() -> Response:
    try:
        record = require_api_key()
    except PermissionError as e:
        return jsonify({"detail": str(e)}), 401
    except RuntimeError as e:
        return runtime_error_response(e)

    plan = str(record.get("plan", "free")).lower()
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    used = int(record.get("checks_used_this_month", 0))
    usage_pct = int((used * 100) / max(1, limits["checks_per_month"]))
    if used > 0 and usage_pct == 0:
        usage_pct = 1

    return jsonify(
        {
            "plan": plan,
            "checks_used_this_month": used,
            "checks_limit": limits["checks_per_month"],
            "checks_remaining": max(0, limits["checks_per_month"] - used),
            "usage_percent": usage_pct,
            "max_chars": limits["max_chars"],
            "batch_limit": limits["batch_limit"],
            "billing_period": record.get("month_reset") or month_key(),
            "upgrade_recommended": plan == "free" and usage_pct >= 70,
            "upgrade_url": plan_checkout_url("starter") if plan == "free" else "",
        }
    )


@app.route("/v1/check", methods=["POST"])
def check_endpoint() -> Response:
    try:
        key_record = require_api_key()
        payload = parse_payload()
        result = run_single_check(payload, key_record, count_usage=True)
        return jsonify(result)
    except PermissionError as e:
        return jsonify({"detail": str(e)}), 401
    except RuntimeError as e:
        return runtime_error_response(e)
    except ValueError as e:
        return jsonify({"detail": str(e)}), 400


@app.route("/v1/batch", methods=["POST"])
def batch_endpoint() -> Response:
    try:
        key_record = require_api_key()
        payload = parse_payload()
        items = payload.get("items")
        if not isinstance(items, list) or not items:
            raise ValueError("items array is required")

        plan = str(key_record.get("plan", "free")).lower()
        limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
        if len(items) > limits["batch_limit"]:
            raise ValueError(f"batch exceeds limit for {plan} plan")
        used = int(key_record.get("checks_used_this_month", 0))
        remaining = max(0, limits["checks_per_month"] - used)
        if len(items) > remaining:
            raise RuntimeError("monthly_limit_exceeded")

        regulations = resolve_regulations(payload.get("regulations"))
        results = []
        for idx, item in enumerate(items):
            row = item if isinstance(item, dict) else {"text": str(item)}
            merged = {
                "text": row.get("text", ""),
                "regulations": regulations,
                "content_type": row.get("content_type", "text"),
            }
            try:
                result = run_single_check(merged, key_record, count_usage=True)
                result["id"] = row.get("id") or str(idx + 1)
                results.append({"success": True, "result": result})
            except ValueError as err:
                results.append({"success": False, "id": row.get("id") or str(idx + 1), "error": str(err)})

        return jsonify(
            {
                "total": len(items),
                "successful": sum(1 for r in results if r.get("success")),
                "results": results,
            }
        )
    except PermissionError as e:
        return jsonify({"detail": str(e)}), 401
    except RuntimeError as e:
        return runtime_error_response(e)
    except ValueError as e:
        return jsonify({"detail": str(e)}), 400


@app.route("/v1/mcp/tools", methods=["GET"])
def mcp_tools() -> Response:
    if not PUBLIC_MCP_TOOLS_ENABLED:
        return jsonify({"detail": "Not found"}), 404
    return jsonify({"tools": tool_definitions()})


@app.route("/mcp", methods=["POST"])
def mcp_transport() -> Response:
    try:
        key_record = require_api_key()
    except PermissionError as e:
        return jsonify({"jsonrpc": "2.0", "error": {"code": -32001, "message": str(e)}, "id": None}), 401
    except RuntimeError as e:
        msg = str(e)
        if msg.startswith("rate_limit_exceeded:"):
            return jsonify({"jsonrpc": "2.0", "error": {"code": -32003, "message": "rate_limit_exceeded"}, "id": None}), 429
        return jsonify({"jsonrpc": "2.0", "error": {"code": -32002, "message": msg}, "id": None}), 429

    payload = request.get_json(silent=True) or {}
    method = payload.get("method")
    req_id = payload.get("id")

    if method == "tools/list":
        return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tool_definitions()}})

    if method == "tools/call":
        params = payload.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}

        if name == "check_compliance":
            try:
                result = run_single_check(arguments, key_record, count_usage=True)
                return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result)}]}})
            except ValueError as e:
                return jsonify({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": str(e)}})

        if name == "check_batch_compliance":
            items = arguments.get("items") if isinstance(arguments, dict) else None
            if not isinstance(items, list) or not items:
                return jsonify({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "items array is required"}})
            plan = str(key_record.get("plan", "free")).lower()
            limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
            if len(items) > limits["batch_limit"]:
                return jsonify({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": f"batch exceeds limit for {plan} plan"}})
            used = int(key_record.get("checks_used_this_month", 0))
            remaining = max(0, limits["checks_per_month"] - used)
            if len(items) > remaining:
                return jsonify({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32002, "message": "monthly_limit_exceeded"}})

            regulations = resolve_regulations(arguments.get("regulations"))
            results = []
            for idx, item in enumerate(items):
                row = item if isinstance(item, dict) else {"text": str(item)}
                merged = {
                    "text": row.get("text", ""),
                    "regulations": regulations,
                    "content_type": row.get("content_type", "text"),
                }
                try:
                    result = run_single_check(merged, key_record, count_usage=True)
                    result["id"] = row.get("id") or str(idx + 1)
                    results.append({"success": True, "result": result})
                except ValueError as err:
                    results.append({"success": False, "id": row.get("id") or str(idx + 1), "error": str(err)})

            mcp_payload = {
                "total": len(items),
                "successful": sum(1 for r in results if r.get("success")),
                "results": results,
            }
            return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(mcp_payload)}]}})

        if name == "compliance_usage_status":
            fresh_record = reset_usage_if_needed(key_record["api_key"]) or key_record
            plan = str(fresh_record.get("plan", "free")).lower()
            limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
            used = int(fresh_record.get("checks_used_this_month", 0))
            usage_pct = int((used * 100) / max(1, limits["checks_per_month"]))
            if used > 0 and usage_pct == 0:
                usage_pct = 1
            usage_payload = {
                "plan": plan,
                "checks_used_this_month": used,
                "checks_limit": limits["checks_per_month"],
                "checks_remaining": max(0, limits["checks_per_month"] - used),
                "usage_percent": usage_pct,
                "max_chars": limits["max_chars"],
                "batch_limit": limits["batch_limit"],
                "upgrade_recommended": plan == "free" and usage_pct >= 70,
                "upgrade_url": plan_checkout_url("starter") if plan == "free" else "",
            }
            return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(usage_payload)}]}})

        return jsonify({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {name}"}})

    return jsonify({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Unsupported method"}})


@app.route("/.well-known/ai-plugin.json", methods=["GET"])
def ai_plugin() -> Response:
    if not PUBLIC_DOCS_ENABLED:
        return jsonify({"detail": "Not found"}), 404
    base = external_base_url()
    return jsonify(
        {
            "schema_version": "v1",
            "name_for_human": "CheckAPI",
            "name_for_model": "checkapi",
            "description_for_human": "Compliance validation guardrail for AI outputs",
            "description_for_model": "Validate text and document outputs against GDPR, HIPAA, CCPA, SOC2, ADA before final answer.",
            "auth": {"type": "service_http", "authorization_type": "bearer"},
            "api": {"type": "openapi", "url": f"{base}/openapi.json"},
            "logo_url": f"{base}/logo-192.png",
            "contact_email": FOLLOWUP_INBOX_EMAIL,
            "legal_info_url": base,
        }
    )


@app.route("/.well-known/agent-offer.json", methods=["GET"])
def agent_offer() -> Response:
    if not PUBLIC_DISCOVERY_ENABLED:
        return jsonify({"detail": "Not found"}), 404
    base = external_base_url()
    return jsonify(
        {
            "name": "CheckAPI",
            "company": "DataWeaveAI company",
            "product_type": "agent-native compliance validation",
            "url": base,
            "value_proposition": (
                "MCP-first compliance guardrail for AI agents with pass/fail, risk scoring, "
                "evidence flags, and remediation output."
            ),
            "pricing": {
                "starter_usd_month": 29,
                "pro_usd_month": 99,
                "scale_usd_month": 299,
                "done_for_you_setup_usd": 2500,
                "full_stack_starter_usd_month": 656,
                "full_stack_launch_due_today_usd": 3156,
            },
            "primary_paths": [
                {
                    "path": "self_serve_starter",
                    "cta": plan_checkout_url("starter"),
                    "description": "Start paid plan for 5,000 checks/month.",
                },
                {
                    "path": "self_serve_pro",
                    "cta": plan_checkout_url("pro"),
                    "description": "Scale to production with higher limits.",
                },
                {
                    "path": "done_for_you_setup",
                    "cta": SETUP_PAYMENT_LINK,
                    "description": "Managed setup and onboarding by DataWeave team.",
                },
                {
                    "path": "dataweave_bundle_monthly",
                    "cta": AGENT_ROUTER_BUNDLE_MONTHLY_URL,
                    "description": "Start all 4 DataWeave services at $656/month.",
                },
                {
                    "path": "dataweave_bundle_full_launch",
                    "cta": AGENT_ROUTER_BUNDLE_FULL_URL,
                    "description": "Pay $3,156 today (setup + first month), then $656/month.",
                },
            ],
            "docs_path": {"cta": f"{base}/docs", "description": "Integration docs and paid onboarding paths."},
            "discoverability": {
                "llms": f"{base}/llms.txt",
                "openapi": f"{base}/openapi.json",
                "stack_manifest": f"{base}/v1/public/stack",
            },
            "bundle_links": {
                "extractapi": EXTRACT_API_URL,
                "redactapi": REDACT_API_URL,
                "agent_router": AGENT_ROUTER_URL,
                "bundle_dashboard": AGENT_ROUTER_BUNDLE_DASHBOARD_URL,
                "bundle_monthly_checkout": AGENT_ROUTER_BUNDLE_MONTHLY_URL,
                "bundle_full_checkout": AGENT_ROUTER_BUNDLE_FULL_URL,
            },
            "security": {"api_key_required": True, "rate_limited": True, "public_discovery": PUBLIC_DISCOVERY_ENABLED},
        }
    )


@app.route("/api/public/lead", methods=["POST"])
def capture_public_lead() -> Response:
    try:
        ip_ok, ip_retry = check_rate_limit("lead_ip", bucketize(client_ip()), CHECKOUT_RATE_LIMIT_PER_MINUTE)
        if not ip_ok:
            raise RuntimeError(f"rate_limit_exceeded:{ip_retry}")

        payload = parse_payload()
        email = clean_text(payload.get("email"), max_len=255).lower()
        plan = clean_text(payload.get("plan"), max_len=20).lower()
        source = clean_text(payload.get("source"), max_len=120) or "site"
        blocked_reason = blocked_checkout_email_reason(email)
        if blocked_reason:
            raise ValueError(blocked_reason)
        if plan not in {"setup", "starter", "pro", "scale"}:
            raise ValueError("Invalid plan")

        link = payment_link_for_plan(plan)
        if not link or "replace_" in link:
            return jsonify({"detail": "Plan checkout unavailable"}), 503

        utm = {
            "utm_source": clean_text(payload.get("utm_source"), max_len=100),
            "utm_medium": clean_text(payload.get("utm_medium"), max_len=100),
            "utm_campaign": clean_text(payload.get("utm_campaign"), max_len=120),
            "utm_content": clean_text(payload.get("utm_content"), max_len=120),
            "utm_term": clean_text(payload.get("utm_term"), max_len=120),
        }

        record_sales_lead(email, plan, source, utm)
        checkout_url = checkout_link_with_prefilled_email(link, email)

        if FOLLOWUP_INBOX_EMAIL:
            send_followup_email(
                FOLLOWUP_INBOX_EMAIL,
                f"CheckAPI lead captured: {plan}",
                (
                    f"<p><b>Email:</b> {email}</p>"
                    f"<p><b>Plan intent:</b> {plan}</p>"
                    f"<p><b>Source:</b> {source}</p>"
                    f"<p><b>Checkout URL:</b> <a href=\"{checkout_url}\">{checkout_url}</a></p>"
                    f"<p><b>UTM:</b> source={utm['utm_source']}, medium={utm['utm_medium']}, campaign={utm['utm_campaign']}</p>"
                ),
            )

        return jsonify({"checkout_url": checkout_url, "plan": plan, "captured": True})
    except ValueError as e:
        return jsonify({"detail": str(e)}), 400
    except RuntimeError as e:
        return runtime_error_response(e)


@app.route("/api/checkout", methods=["POST"])
def create_checkout() -> Response:
    if not SELF_SERVE_CHECKOUT_ENABLED:
        return jsonify({"detail": "Self-serve checkout disabled"}), 403
    if not stripe or not STRIPE_SECRET_KEY:
        return jsonify({"detail": "Stripe not configured"}), 503

    try:
        ip_ok, ip_retry = check_rate_limit("checkout_ip", bucketize(client_ip()), CHECKOUT_RATE_LIMIT_PER_MINUTE)
        if not ip_ok:
            raise RuntimeError(f"rate_limit_exceeded:{ip_retry}")

        payload = parse_payload()
        email = clean_text(payload.get("email"), max_len=255).lower()
        plan = clean_text(payload.get("plan"), max_len=20).lower()
        blocked_reason = blocked_checkout_email_reason(email)
        if blocked_reason:
            raise ValueError(blocked_reason)
        email_ok, email_retry = check_rate_limit("checkout_email", bucketize(email), CHECKOUT_RATE_LIMIT_PER_MINUTE)
        if not email_ok:
            raise RuntimeError(f"rate_limit_exceeded:{email_retry}")
        if plan not in {"starter", "pro", "scale"}:
            raise ValueError("Invalid plan")

        price_id = STRIPE_PRICE_IDS.get(plan)
        if not price_id:
            raise ValueError("Plan not configured")

        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            customer_email=email,
            success_url=f"{external_base_url()}/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{external_base_url()}/?checkout=cancelled",
            metadata={"email": email, "plan": plan, "product": "checkapi"},
        )

        if FOLLOWUP_INBOX_EMAIL:
            send_followup_email(
                FOLLOWUP_INBOX_EMAIL,
                f"CheckAPI checkout started: {plan}",
                (
                    f"<p><b>Email:</b> {email}</p>"
                    f"<p><b>Plan:</b> {plan}</p>"
                    f"<p><b>Session ID:</b> {session.id}</p>"
                ),
            )

        return jsonify({"checkout_url": session.url, "session_id": session.id})
    except ValueError as e:
        return jsonify({"detail": str(e)}), 400
    except RuntimeError as e:
        return runtime_error_response(e)
    except stripe.StripeError as e:  # type: ignore[union-attr]
        return jsonify({"detail": str(e)}), 400


@app.route("/api/checkout/start", methods=["GET"])
def checkout_start() -> Response:
    if not SELF_SERVE_CHECKOUT_ENABLED:
        return jsonify({"detail": "Self-serve checkout disabled"}), 403
    if not stripe or not STRIPE_SECRET_KEY:
        return jsonify({"detail": "Stripe not configured"}), 503

    try:
        ip_ok, ip_retry = check_rate_limit("checkout_start_ip", bucketize(client_ip()), CHECKOUT_RATE_LIMIT_PER_MINUTE)
        if not ip_ok:
            raise RuntimeError(f"rate_limit_exceeded:{ip_retry}")

        plan = clean_text(request.args.get("plan"), max_len=20).lower()
        email = clean_text(request.args.get("email"), max_len=255).lower()
        if plan not in {"starter", "pro", "scale"}:
            raise ValueError("Invalid plan")
        blocked_reason = blocked_checkout_email_reason(email)
        if blocked_reason:
            raise ValueError(blocked_reason)

        price_id = STRIPE_PRICE_IDS.get(plan)
        if not price_id:
            raise ValueError("Plan not configured")

        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            customer_email=email,
            success_url=f"{external_base_url()}/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{external_base_url()}/?checkout=cancelled",
            metadata={"plan": plan, "product": "checkapi", "source": "checkout_start", "email": email},
            allow_promotion_codes=True,
        )
        return redirect(session.url, code=303)
    except ValueError as e:
        return jsonify({"detail": str(e)}), 400
    except RuntimeError as e:
        return runtime_error_response(e)
    except stripe.StripeError as e:  # type: ignore[union-attr]
        return jsonify({"detail": str(e)}), 400


@app.route("/api/stripe/webhook", methods=["POST"])
def stripe_webhook() -> Response:
    if not stripe or not STRIPE_WEBHOOK_SECRET:
        return jsonify({"detail": "Webhook not configured"}), 503

    ip_ok, ip_retry = check_rate_limit("webhook_ip", bucketize(client_ip()), WEBHOOK_RATE_LIMIT_PER_MINUTE)
    if not ip_ok:
        resp = jsonify({"detail": "rate_limit_exceeded"})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(ip_retry)
        return resp

    payload = request.get_data()
    sig = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return jsonify({"detail": "Invalid signature"}), 400

    event_type = event.get("type", "")

    if event_type == "checkout.session.completed":
        session = event.get("data", {}).get("object", {})
        session_id = session.get("id", "")
        email = (
            session.get("customer_email")
            or (session.get("customer_details") or {}).get("email")
            or (session.get("metadata") or {}).get("email")
            or ""
        ).lower()
        plan = infer_plan_from_checkout_session(session)

        if email:
            with conn() as c:
                existing = c.execute("SELECT api_key FROM api_keys WHERE email = ?", (email,)).fetchone()
            api_key = ""
            if existing:
                api_key = str(existing["api_key"])
                with conn() as c:
                    c.execute(
                        """
                        UPDATE api_keys
                        SET plan = ?, stripe_customer_id = ?, stripe_subscription_id = ?, updated_at = ?
                        WHERE email = ?
                        """,
                        (plan, session.get("customer"), session.get("subscription"), now_iso(), email),
                    )
            else:
                key = create_api_key(email, plan)
                api_key = key
                with conn() as c:
                    c.execute(
                        """
                        UPDATE api_keys
                        SET stripe_customer_id = ?, stripe_subscription_id = ?, updated_at = ?
                        WHERE api_key = ?
                        """,
                        (session.get("customer"), session.get("subscription"), now_iso(), key),
                    )

            if session_id and mark_notification_sent(session_id, "paid_checkout") and FOLLOWUP_INBOX_EMAIL:
                amount = session.get("amount_total")
                amount_txt = f"${(amount or 0) / 100:.2f}" if amount is not None else "n/a"
                send_followup_email(
                    FOLLOWUP_INBOX_EMAIL,
                    f"CheckAPI payment completed: {plan}",
                    (
                        f"<p><b>Email:</b> {email}</p>"
                        f"<p><b>Plan:</b> {plan}</p>"
                        f"<p><b>Amount:</b> {amount_txt}</p>"
                        f"<p><b>Session ID:</b> {session_id}</p>"
                    ),
                )
            if session_id and mark_notification_sent(session_id, "access_delivery") and api_key:
                send_followup_email(
                    email,
                    "Your CheckAPI access is active",
                    (
                        f"<h2>CheckAPI Plan Activated</h2>"
                        f"<p><b>Plan:</b> {plan}</p>"
                        f"<p><b>API Key:</b> <code>{api_key}</code></p>"
                        f"<p>Docs: <a href=\"{external_base_url()}/docs\">{external_base_url()}/docs</a></p>"
                        f"<p>Usage: <a href=\"{external_base_url()}/v1/usage\">{external_base_url()}/v1/usage</a></p>"
                    ),
                )

    elif event_type == "customer.subscription.deleted":
        sub = event.get("data", {}).get("object", {})
        sub_id = sub.get("id")
        if sub_id:
            with conn() as c:
                c.execute(
                    "UPDATE api_keys SET plan = 'free', updated_at = ? WHERE stripe_subscription_id = ?",
                    (now_iso(), sub_id),
                )

    return jsonify({"status": "ok"})


@app.route("/api/billing/verify-session", methods=["GET"])
def verify_session() -> Response:
    if not stripe or not STRIPE_SECRET_KEY:
        return jsonify({"verified": False, "reason": "Payments not configured"}), 503
    ip_ok, ip_retry = check_rate_limit("verify_session_ip", bucketize(client_ip()), CHECKOUT_RATE_LIMIT_PER_MINUTE)
    if not ip_ok:
        resp = jsonify({"verified": False, "reason": "rate_limit_exceeded"})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(ip_retry)
        return resp

    session_id = clean_text(request.args.get("session_id"), max_len=255)
    if not session_id:
        return jsonify({"verified": False, "reason": "Missing session_id"}), 400

    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.get("payment_status") == "paid":
            email = (
                session.get("customer_email")
                or (session.get("customer_details") or {}).get("email")
                or (session.get("metadata") or {}).get("email")
                or ""
            ).lower()
            plan = infer_plan_from_checkout_session(session)

            api_key = ""
            if email and EMAIL_RE.match(email):
                existing = get_key_record_by_email(email)
                if existing:
                    api_key = str(existing.get("api_key") or "")
                    with conn() as c:
                        c.execute(
                            """
                            UPDATE api_keys
                            SET plan = ?, stripe_customer_id = ?, stripe_subscription_id = ?, updated_at = ?
                            WHERE email = ?
                            """,
                            (plan, session.get("customer"), session.get("subscription"), now_iso(), email),
                        )
                else:
                    api_key = create_api_key(email, plan)
                    with conn() as c:
                        c.execute(
                            """
                            UPDATE api_keys
                            SET stripe_customer_id = ?, stripe_subscription_id = ?, updated_at = ?
                            WHERE api_key = ?
                            """,
                            (session.get("customer"), session.get("subscription"), now_iso(), api_key),
                        )

                if mark_notification_sent(session_id, "access_delivery_verify") and api_key and RESEND_API_KEY:
                    send_followup_email(
                        email,
                        "Your CheckAPI access is active",
                        (
                            f"<h2>CheckAPI Plan Activated</h2>"
                            f"<p><b>Plan:</b> {plan}</p>"
                            f"<p><b>API Key:</b> <code>{api_key}</code></p>"
                            f"<p>Docs: <a href=\"{external_base_url()}/docs\">{external_base_url()}/docs</a></p>"
                            f"<p>Usage: <a href=\"{external_base_url()}/v1/usage\">{external_base_url()}/v1/usage</a></p>"
                        ),
                    )

            return jsonify(
                {
                    "verified": True,
                    "plan": plan,
                    "email": email or None,
                }
            )
        return jsonify({"verified": False, "reason": "Payment not completed"})
    except stripe.StripeError:
        return jsonify({"verified": False, "reason": "Payment verification failed"})


@app.route("/api/access/resend-key", methods=["POST"])
def resend_access_key() -> Response:
    try:
        ip_ok, ip_retry = check_rate_limit("resend_access_ip", bucketize(client_ip()), CHECKOUT_RATE_LIMIT_PER_MINUTE)
        if not ip_ok:
            raise RuntimeError(f"rate_limit_exceeded:{ip_retry}")

        payload = parse_payload()
        email = clean_text(payload.get("email"), max_len=255).lower()
        blocked_reason = blocked_checkout_email_reason(email)
        if blocked_reason:
            raise ValueError(blocked_reason)
        record = get_key_record_by_email(email)
        if record and RESEND_API_KEY:
            send_followup_email(
                email,
                "Your CheckAPI key details",
                (
                    f"<h2>CheckAPI Access</h2>"
                    f"<p><b>Plan:</b> {record.get('plan', 'free')}</p>"
                    f"<p><b>API Key:</b> <code>{record.get('api_key')}</code></p>"
                    f"<p>Docs: <a href=\"{external_base_url()}/docs\">{external_base_url()}/docs</a></p>"
                ),
            )
        return jsonify({"status": "accepted"})
    except ValueError as e:
        return jsonify({"detail": str(e)}), 400
    except RuntimeError as e:
        return runtime_error_response(e)


@app.route("/v1/public/stack", methods=["GET"])
def public_stack() -> Response:
    base = external_base_url()
    return jsonify(dataweave_stack_payload(base))


@app.route("/.well-known/dataweave-stack.json", methods=["GET"])
def dataweave_stack_well_known() -> Response:
    if not PUBLIC_DISCOVERY_ENABLED:
        return jsonify({"detail": "Not found"}), 404
    base = external_base_url()
    return jsonify(dataweave_stack_payload(base))


@app.route("/v1/public/config", methods=["GET"])
def public_config() -> Response:
    return jsonify(
        {
            "product": "checkapi",
            "base_url": external_base_url(),
            "payment_ready": not STARTER_PAYMENT_LINK.startswith("https://buy.stripe.com/replace"),
            "setup_payment_link": SETUP_PAYMENT_LINK,
            "starter_payment_link": plan_checkout_url("starter"),
            "pro_payment_link": plan_checkout_url("pro"),
            "scale_payment_link": plan_checkout_url("scale"),
            "stack_manifest": external_base_url() + "/v1/public/stack",
            "stack_services": {
                "dataweave_home": DATAWEAVE_HOME_URL,
                "extractapi": EXTRACT_API_URL,
                "redactapi": REDACT_API_URL,
                "agent_router": AGENT_ROUTER_URL,
            },
            "bundle": {
                "monthly_usd": 656,
                "full_launch_due_today_usd": 3156,
                "dashboard_url": AGENT_ROUTER_BUNDLE_DASHBOARD_URL,
                "monthly_checkout_url": AGENT_ROUTER_BUNDLE_MONTHLY_URL,
                "full_launch_checkout_url": AGENT_ROUTER_BUNDLE_FULL_URL,
            },
            "plans": {
                "starter": 5000,
                "pro": 25000,
                "scale": 100000,
            },
            "time": now_iso(),
        }
    )


@app.route("/robots.txt", methods=["GET"])
def robots() -> Response:
    base = external_base_url()
    if not PUBLIC_DISCOVERY_ENABLED:
        return Response("User-agent: *\nDisallow: /\n", mimetype="text/plain")

    body = (
        "User-agent: *\n"
        "Allow: /\n"
        "Allow: /v1/public/stack\n"
        "Allow: /.well-known/dataweave-stack.json\n"
        "Allow: /.well-known/agent-offer.json\n"
        "Allow: /llms.txt\n"
        "Disallow: /v1/\n"
        "Disallow: /api/\n"
        "Sitemap: " + base + "/sitemap.xml\n"
    )
    return Response(body, mimetype="text/plain")


@app.route("/llms.txt", methods=["GET"])
def llms() -> Response:
    if not PUBLIC_DISCOVERY_ENABLED:
        return Response("Not found", status=404)
    path = LANDING_DIR / "llms.txt"
    if not path.exists():
        return Response("# CheckAPI\nAgent-native compliance guardrail", mimetype="text/plain")
    content = (
        path.read_text(encoding="utf-8")
        .replace("{{BASE_URL}}", external_base_url())
        .replace("{{DATAWEAVE_HOME_URL}}", DATAWEAVE_HOME_URL)
        .replace("{{EXTRACT_API_URL}}", EXTRACT_API_URL)
        .replace("{{REDACT_API_URL}}", REDACT_API_URL)
        .replace("{{AGENT_ROUTER_URL}}", AGENT_ROUTER_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_MONTHLY_URL}}", AGENT_ROUTER_BUNDLE_MONTHLY_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_FULL_URL}}", AGENT_ROUTER_BUNDLE_FULL_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_DASHBOARD_URL}}", AGENT_ROUTER_BUNDLE_DASHBOARD_URL)
    )
    return Response(content, mimetype="text/plain")


@app.route("/llms-full.txt", methods=["GET"])
def llms_full() -> Response:
    return llms()


@app.route("/sitemap.xml", methods=["GET"])
def sitemap() -> Response:
    base = external_base_url()
    urls = [
        f"{base}/",
        f"{base}/docs",
        f"{base}/llms.txt",
        f"{base}/v1/public/stack",
        f"{base}/.well-known/dataweave-stack.json",
        f"{base}/.well-known/agent-offer.json",
        f"{base}/openapi.json",
    ]
    rows = "\n".join([f"  <url><loc>{u}</loc></url>" for u in urls])
    xml = f"""<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n{rows}\n</urlset>
"""
    return Response(xml, mimetype="application/xml")


@app.route("/indexnow-key.txt", methods=["GET"])
def indexnow_file() -> Response:
    if not INDEXNOW_KEY:
        return Response("Not found", status=404)
    return Response(INDEXNOW_KEY + "\n", mimetype="text/plain")


@app.route("/<path:filename>", methods=["GET"])
def static_files(filename: str):
    # static assets from landing folder
    static_names = {
        "favicon.ico",
        "favicon-16.png",
        "favicon-32.png",
        "logo-192.png",
        "logo-512.png",
        "og-image.png",
    }
    if filename in static_names:
        file_path = LANDING_DIR / filename
        if file_path.exists():
            return send_from_directory(str(LANDING_DIR), filename)
    return Response("Not found", status=404)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
