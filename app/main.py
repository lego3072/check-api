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

from flask import Flask, Response, jsonify, request, send_from_directory
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
INDEXNOW_KEY = os.getenv("INDEXNOW_KEY", "").strip()
CORS_ALLOW_ORIGINS_RAW = os.getenv("CORS_ALLOW_ORIGINS", "").strip()

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

MAX_TEXT_CHARS_GLOBAL = env_int("MAX_TEXT_CHARS_GLOBAL", 120000)
MAX_REQUEST_BYTES = env_int("MAX_REQUEST_BYTES", 1_200_000)

SIGNUP_RATE_LIMIT_PER_MINUTE = env_int("SIGNUP_RATE_LIMIT_PER_MINUTE", 8)
CHECKOUT_RATE_LIMIT_PER_MINUTE = env_int("CHECKOUT_RATE_LIMIT_PER_MINUTE", 20)
WEBHOOK_RATE_LIMIT_PER_MINUTE = env_int("WEBHOOK_RATE_LIMIT_PER_MINUTE", 120)
API_RATE_LIMIT_PER_KEY_PER_MINUTE = env_int("API_RATE_LIMIT_PER_KEY_PER_MINUTE", 240)
API_RATE_LIMIT_PER_IP_PER_MINUTE = env_int("API_RATE_LIMIT_PER_IP_PER_MINUTE", 360)
RATE_LIMIT_WINDOW_SECONDS = env_int("RATE_LIMIT_WINDOW_SECONDS", 60)

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


def month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def get_key_record(api_key: str) -> dict[str, Any] | None:
    with conn() as c:
        row = c.execute("SELECT * FROM api_keys WHERE api_key = ?", (api_key,)).fetchone()
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


def runtime_error_response(err: RuntimeError) -> Response:
    msg = str(err)
    if msg.startswith("rate_limit_exceeded:"):
        retry_after = msg.split(":", 1)[1].strip() or "60"
        resp = jsonify({"detail": "rate_limit_exceeded"})
        resp.status_code = 429
        resp.headers["Retry-After"] = retry_after
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
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    used = int(record.get("checks_used_this_month", 0))

    if used >= limits["checks_per_month"]:
        raise RuntimeError("monthly_limit_exceeded")

    return record


def increment_usage(api_key: str, delta: int = 1) -> None:
    with conn() as c:
        c.execute(
            """
            UPDATE api_keys
            SET checks_used_this_month = checks_used_this_month + ?, updated_at = ?
            WHERE api_key = ?
            """,
            (max(1, delta), now_iso(), api_key),
        )


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


def record_check(api_key: str, request_id: str, result: dict[str, Any], regulation_count: int, content_type: str) -> None:
    with conn() as c:
        c.execute(
            """
            INSERT INTO compliance_checks
            (api_key, request_id, regulation_count, risk_score, severity, flag_count, content_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                api_key,
                request_id,
                regulation_count,
                int(result.get("risk_score", 0)),
                str(result.get("severity", "none")),
                int(result.get("flag_count", 0)),
                content_type,
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
        increment_usage(key_record["api_key"], 1)
        request_id = "chk_" + secrets.token_hex(8)
        record_check(key_record["api_key"], request_id, result, len(regulations), content_type)
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
        .replace("{{SETUP_PAYMENT_LINK}}", SETUP_PAYMENT_LINK)
        .replace("{{STARTER_PAYMENT_LINK}}", STARTER_PAYMENT_LINK)
        .replace("{{PRO_PAYMENT_LINK}}", PRO_PAYMENT_LINK)
        .replace("{{SCALE_PAYMENT_LINK}}", SCALE_PAYMENT_LINK)
    )


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
    if request.is_secure:
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


@app.route("/docs", methods=["GET"])
def docs_page() -> Response:
    html = render_landing("docs.html")
    if html:
        return Response(html, mimetype="text/html")
    return jsonify({"openapi": external_base_url() + "/openapi.json"})


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
                        "max_chars": {"type": "integer"},
                        "batch_limit": {"type": "integer"},
                        "billing_period": {"type": "string"},
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
                    "summary": "Create free API key",
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
        ip_ok, ip_retry = check_rate_limit("signup_ip", bucketize(client_ip()), SIGNUP_RATE_LIMIT_PER_MINUTE)
        if not ip_ok:
            raise RuntimeError(f"rate_limit_exceeded:{ip_retry}")

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

        api_key = create_api_key(email, "free")

        send_followup_email(
            email,
            "Your CheckAPI key is ready",
            (
                f"<h2>CheckAPI Free Tier Enabled</h2>"
                f"<p>API key: <code>{api_key}</code></p>"
                f"<p>Free plan includes 500 checks/month.</p>"
                f"<p>Upgrade: <a href=\"{STARTER_PAYMENT_LINK}\">Starter</a></p>"
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

    return jsonify(
        {
            "plan": plan,
            "checks_used_this_month": used,
            "checks_limit": limits["checks_per_month"],
            "checks_remaining": max(0, limits["checks_per_month"] - used),
            "max_chars": limits["max_chars"],
            "batch_limit": limits["batch_limit"],
            "billing_period": record.get("month_reset") or month_key(),
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
    if not PUBLIC_DOCS_ENABLED:
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
            usage_payload = {
                "plan": plan,
                "checks_used_this_month": used,
                "checks_limit": limits["checks_per_month"],
                "checks_remaining": max(0, limits["checks_per_month"] - used),
                "max_chars": limits["max_chars"],
                "batch_limit": limits["batch_limit"],
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
        if not EMAIL_RE.match(email):
            raise ValueError("Valid email required")
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
            success_url=f"{external_base_url()}/?payment=success&session_id={{CHECKOUT_SESSION_ID}}",
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
        email = (session.get("customer_email") or session.get("metadata", {}).get("email") or "").lower()
        plan = (session.get("metadata", {}).get("plan") or "starter").lower()

        if email:
            with conn() as c:
                existing = c.execute("SELECT api_key FROM api_keys WHERE email = ?", (email,)).fetchone()
            if existing:
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
            return jsonify(
                {
                    "verified": True,
                    "plan": (session.get("metadata", {}) or {}).get("plan", "starter"),
                    "email": session.get("customer_email"),
                }
            )
        return jsonify({"verified": False, "reason": "Payment not completed"})
    except stripe.StripeError:
        return jsonify({"verified": False, "reason": "Payment verification failed"})


@app.route("/v1/public/config", methods=["GET"])
def public_config() -> Response:
    return jsonify(
        {
            "product": "checkapi",
            "base_url": external_base_url(),
            "payment_ready": not STARTER_PAYMENT_LINK.startswith("https://buy.stripe.com/replace"),
            "setup_payment_link": SETUP_PAYMENT_LINK,
            "starter_payment_link": STARTER_PAYMENT_LINK,
            "pro_payment_link": PRO_PAYMENT_LINK,
            "scale_payment_link": SCALE_PAYMENT_LINK,
            "plans": {
                "free": 500,
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
        "Allow: /v1/mcp/tools\n"
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
    content = path.read_text(encoding="utf-8").replace("{{BASE_URL}}", external_base_url())
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
        f"{base}/v1/mcp/tools",
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
