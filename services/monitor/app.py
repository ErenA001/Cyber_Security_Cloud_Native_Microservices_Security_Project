from __future__ import annotations

import hmac
import json
import math
import os
import re
import sqlite3
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from shared.security import require_admin, require_same_origin_request

DB_PATH = Path(os.getenv("MONITOR_DATABASE_PATH", "/data/events.db"))
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
EVENT_TYPE_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
SOURCE_RE = re.compile(r"^[a-zA-Z0-9_.-]{2,40}$")
ALLOWED_DETAIL_KEYS = {
    "reason", "method", "role", "route", "control", "scenario", "attempts",
    "window_seconds", "component", "finding", "status_code", "model", "provider",
    "result", "package", "severity", "cve", "request_id", "count", "duration_ms",
    "image", "scanner", "critical", "high", "medium", "low", "unknown",
    "passed", "failed", "assessment", "vulnerabilities", "misconfigurations", "secrets",
}
SCAN_SUMMARY_KEYS = {"critical", "high", "medium", "low", "unknown", "vulnerabilities", "misconfigurations", "secrets"}
SCAN_FINDING_KEYS = {
    "id", "package", "installed_version", "fixed_version", "severity", "title",
    "target", "class", "type", "primary_url", "message", "rule_id", "category", "start_line",
}


class EventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    source: str = Field(min_length=2, max_length=40, pattern=r"^[a-zA-Z0-9_.-]+$")
    severity: Literal["INFO", "WARNING", "CRITICAL"] = "INFO"
    actor: str | None = Field(default=None, max_length=64)
    details: dict[str, object] = Field(default_factory=dict)
    request_id: str | None = Field(default=None, max_length=64)


class SimulateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: Literal["brute_force", "unauthorized_api", "container_risk", "prompt_injection", "rate_limit"]


class ScanReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    image: str = Field(min_length=1, max_length=240)
    image_id: str | None = Field(default=None, max_length=200)
    scanner: Literal["Trivy"] = "Trivy"
    scanner_version: str = Field(min_length=1, max_length=40)
    scanner_metadata: dict[str, object] = Field(default_factory=dict)
    scan_status: Literal["completed", "failed"] = "completed"
    summary: dict[str, int] = Field(default_factory=dict)
    findings: list[dict[str, object]] = Field(default_factory=list, max_length=100)


class AssessmentReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=100)
    status: Literal["passed", "failed", "partial"]
    passed: int = Field(ge=0, le=1000)
    failed: int = Field(ge=0, le=1000)
    checks: list[dict[str, object]] = Field(default_factory=list, max_length=60)


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 15000")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def db_session():
    connection = connect_db()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db_session() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                actor TEXT,
                details_json TEXT NOT NULL,
                request_id TEXT
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scan_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                image TEXT NOT NULL,
                image_id TEXT,
                scanner TEXT NOT NULL,
                scanner_version TEXT NOT NULL,
                scanner_metadata_json TEXT NOT NULL DEFAULT '{}',
                scan_status TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                findings_json TEXT NOT NULL
            )"""
        )
        scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scan_reports)").fetchall()}
        if "image_id" not in scan_columns:
            connection.execute("ALTER TABLE scan_reports ADD COLUMN image_id TEXT")
        if "scanner_metadata_json" not in scan_columns:
            connection.execute("ALTER TABLE scan_reports ADD COLUMN scanner_metadata_json TEXT NOT NULL DEFAULT '{}'")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_scan_reports_created_at ON scan_reports(created_at)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS assessment_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                passed INTEGER NOT NULL,
                failed INTEGER NOT NULL,
                checks_json TEXT NOT NULL
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_assessment_reports_created_at ON assessment_reports(created_at)")


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="CloudGuard Monitoring Service", version="2.0.0", docs_url=None, redoc_url=None, lifespan=lifespan)


def clean_details(details: dict[str, object]) -> dict[str, object]:
    cleaned: dict[str, object] = {}
    for key, value in details.items():
        if key not in ALLOWED_DETAIL_KEYS:
            continue
        if isinstance(value, bool) or value is None:
            cleaned[key] = value
        elif isinstance(value, int):
            cleaned[key] = value
        elif isinstance(value, float) and math.isfinite(value):
            cleaned[key] = value
        elif isinstance(value, str):
            cleaned[key] = value[:160]
    return cleaned


def store_event(event: EventCreate) -> dict[str, object]:
    if not EVENT_TYPE_RE.fullmatch(event.event_type) or not SOURCE_RE.fullmatch(event.source):
        raise HTTPException(status_code=422, detail="Invalid event type or source.")
    created_at = now_iso()
    details = clean_details(event.details)
    with db_session() as connection:
        cursor = connection.execute(
            """INSERT INTO events (created_at, event_type, source, severity, actor, details_json, request_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (created_at, event.event_type, event.source, event.severity,
             (event.actor or "")[:64] or None, json.dumps(details, separators=(",", ":")), event.request_id),
        )
        event_id = cursor.lastrowid
    return {
        "id": event_id, "created_at": created_at, "event_type": event.event_type,
        "source": event.source, "severity": event.severity, "actor": event.actor,
        "details": details, "request_id": event.request_id,
    }


def require_service_token(x_service_token: str | None) -> None:
    if not SERVICE_TOKEN or not x_service_token or not hmac.compare_digest(SERVICE_TOKEN, x_service_token):
        raise HTTPException(status_code=401, detail="Invalid service credentials.")


def safe_json(raw: str, fallback):
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return fallback


def row_to_event(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"], "created_at": row["created_at"], "event_type": row["event_type"],
        "source": row["source"], "severity": row["severity"], "actor": row["actor"],
        "details": safe_json(row["details_json"], {}), "request_id": row["request_id"],
    }


def clean_scan_summary(summary: dict[str, int]) -> dict[str, int]:
    cleaned = {}
    for key, value in summary.items():
        if key in SCAN_SUMMARY_KEYS and isinstance(value, int) and not isinstance(value, bool):
            cleaned[key] = max(0, min(value, 1000000))
    return cleaned


def clean_scanner_metadata(metadata: dict[str, object]) -> dict[str, object]:
    allowed = {"version", "vulnerability_db_version", "vulnerability_db_updated_at", "vulnerability_db_next_update", "vulnerability_db_downloaded_at"}
    cleaned: dict[str, object] = {}
    for key, value in metadata.items():
        if key not in allowed:
            continue
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            cleaned[key] = str(value)[:120]
    return cleaned


def clean_scan_findings(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    output = []
    for finding in findings[:100]:
        if not isinstance(finding, dict):
            continue
        item: dict[str, object] = {}
        for key, value in finding.items():
            if key not in SCAN_FINDING_KEYS:
                continue
            if isinstance(value, str):
                item[key] = value[:240]
            elif isinstance(value, int) and not isinstance(value, bool):
                item[key] = value
        if item:
            output.append(item)
    return output


def row_to_scan(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"], "created_at": row["created_at"], "image": row["image"],
        "image_id": row["image_id"], "scanner": row["scanner"], "scanner_version": row["scanner_version"],
        "scanner_metadata": safe_json(row["scanner_metadata_json"], {}),
        "scan_status": row["scan_status"], "summary": safe_json(row["summary_json"], {}),
        "findings": safe_json(row["findings_json"], []),
    }


def row_to_assessment(row: sqlite3.Row) -> dict[str, object]:
    return {
        "id": row["id"], "created_at": row["created_at"], "name": row["name"],
        "status": row["status"], "passed": row["passed"], "failed": row["failed"],
        "checks": safe_json(row["checks_json"], []),
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "monitor", "storage": "sqlite"}


@app.post("/internal/events")
async def internal_create_event(event: EventCreate, x_service_token: str | None = Header(default=None)):
    require_service_token(x_service_token)
    return store_event(event)


@app.get("/internal/recent-events")
async def internal_recent_events(limit: int = Query(default=20, ge=1, le=50), x_service_token: str | None = Header(default=None)):
    require_service_token(x_service_token)
    with db_session() as connection:
        rows = connection.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"events": [row_to_event(row) for row in rows]}


@app.get("/internal/recent-scan-reports")
async def internal_recent_scan_reports(limit: int = Query(default=5, ge=1, le=10), x_service_token: str | None = Header(default=None)):
    require_service_token(x_service_token)
    with db_session() as connection:
        rows = connection.execute("SELECT * FROM scan_reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"scan_reports": [row_to_scan(row) for row in rows]}


@app.get("/summary")
async def summary(user: dict[str, str] = Depends(require_admin)):
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=24)).isoformat(timespec="seconds")
    with db_session() as connection:
        total = connection.execute("SELECT COUNT(*) FROM events WHERE created_at >= ?", (cutoff,)).fetchone()[0]
        all_time = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        severity_rows = connection.execute(
            "SELECT severity, COUNT(*) AS n FROM events WHERE created_at >= ? GROUP BY severity", (cutoff,)
        ).fetchall()
        source_rows = connection.execute(
            "SELECT source, COUNT(*) AS n FROM events WHERE created_at >= ? GROUP BY source ORDER BY n DESC", (cutoff,)
        ).fetchall()
        timeline = []
        for index in range(6):
            bucket_start = now - timedelta(hours=24 - index * 4)
            bucket_end = bucket_start + timedelta(hours=4)
            bucket_rows = connection.execute(
                "SELECT severity, COUNT(*) AS n FROM events WHERE created_at >= ? AND created_at < ? GROUP BY severity",
                (bucket_start.isoformat(timespec="seconds"), bucket_end.isoformat(timespec="seconds")),
            ).fetchall()
            bucket_counts = {row["severity"].lower(): row["n"] for row in bucket_rows}
            timeline.append({"label": bucket_start.strftime("%H:%M"), "critical": bucket_counts.get("critical", 0),
                             "warning": bucket_counts.get("warning", 0), "info": bucket_counts.get("info", 0)})
        latest_scan_row = connection.execute("SELECT * FROM scan_reports ORDER BY id DESC LIMIT 1").fetchone()
        latest_assessment_row = connection.execute("SELECT * FROM assessment_reports ORDER BY id DESC LIMIT 1").fetchone()
    severities = {row["severity"].lower(): row["n"] for row in severity_rows}
    return {
        "period": "24h", "period_start": cutoff, "total_events": total, "all_time_events": all_time,
        "critical": severities.get("critical", 0), "warnings": severities.get("warning", 0),
        "info": severities.get("info", 0),
        "by_source": [{"source": row["source"], "count": row["n"]} for row in source_rows],
        "timeline": timeline,
        "latest_scan": row_to_scan(latest_scan_row) if latest_scan_row else None,
        "latest_assessment": row_to_assessment(latest_assessment_row) if latest_assessment_row else None,
    }


@app.get("/events")
async def get_events(
    limit: int = Query(default=30, ge=1, le=100),
    severity: Literal["INFO", "WARNING", "CRITICAL"] | None = None,
    user: dict[str, str] = Depends(require_admin),
):
    with db_session() as connection:
        if severity:
            rows = connection.execute("SELECT * FROM events WHERE severity = ? ORDER BY id DESC LIMIT ?", (severity, limit)).fetchall()
        else:
            rows = connection.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"events": [row_to_event(row) for row in rows]}


@app.post("/simulate", dependencies=[Depends(require_same_origin_request)])
async def simulate(data: SimulateRequest, request: Request, user: dict[str, str] = Depends(require_admin)):
    scenarios = {
        "brute_force": EventCreate(event_type="auth.brute_force.simulated", source="auth", severity="CRITICAL", actor=user["username"],
            details={"scenario": "brute_force", "attempts": 25, "window_seconds": 60, "control": "Nginx login rate limit"}, request_id=request.headers.get("X-Request-ID")),
        "unauthorized_api": EventCreate(event_type="api.access_denied.simulated", source="gateway", severity="WARNING", actor=user["username"],
            details={"scenario": "unauthorized_api", "route": "/api/ai/chat", "control": "JWT authentication and role checks"}, request_id=request.headers.get("X-Request-ID")),
        "container_risk": EventCreate(event_type="container.vulnerability.simulated", source="container_scanner", severity="WARNING", actor=user["username"],
            details={"scenario": "container_risk", "component": "demo-image", "finding": "Synthetic high-severity image finding", "control": "Trivy image scanning"}, request_id=request.headers.get("X-Request-ID")),
        "prompt_injection": EventCreate(event_type="ai.prompt_injection_signal.simulated", source="ai", severity="WARNING", actor=user["username"],
            details={"scenario": "prompt_injection", "finding": "Prompt-injection pattern in synthetic test input", "control": "Input boundary and human review"}, request_id=request.headers.get("X-Request-ID")),
        "rate_limit": EventCreate(event_type="gateway.rate_limit.simulated", source="gateway", severity="WARNING", actor=user["username"],
            details={"scenario": "rate_limit", "attempts": 40, "window_seconds": 10, "control": "Nginx request throttling"}, request_id=request.headers.get("X-Request-ID")),
    }
    event = store_event(scenarios[data.scenario])
    return {"simulated": True, "event": event, "notice": "Synthetic lab event only; no real attack was executed."}


@app.post("/scan-reports", dependencies=[Depends(require_same_origin_request)])
async def create_scan_report(data: ScanReportCreate, user: dict[str, str] = Depends(require_admin)):
    summary_data = clean_scan_summary(data.summary)
    scanner_metadata = clean_scanner_metadata(data.scanner_metadata)
    findings_data = clean_scan_findings(data.findings)
    created_at = now_iso()
    with db_session() as connection:
        cursor = connection.execute(
            """INSERT INTO scan_reports (created_at, image, image_id, scanner, scanner_version, scanner_metadata_json, scan_status, summary_json, findings_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (created_at, data.image.strip()[:240], (data.image_id or "")[:200] or None, data.scanner, data.scanner_version,
             json.dumps(scanner_metadata, separators=(",", ":")), data.scan_status,
             json.dumps(summary_data, separators=(",", ":")), json.dumps(findings_data, separators=(",", ":"))),
        )
        report_id = cursor.lastrowid
    critical = summary_data.get("critical", 0)
    high = summary_data.get("high", 0)
    severity = "CRITICAL" if critical else "WARNING" if high else "INFO"
    store_event(EventCreate(event_type="container.scan.completed", source="container_scanner", severity=severity,
        actor=user["username"], details={"image": data.image, "scanner": "Trivy", "critical": critical,
        "high": high, "medium": summary_data.get("medium", 0), "vulnerabilities": summary_data.get("vulnerabilities", 0)}))
    with db_session() as connection:
        row = connection.execute("SELECT * FROM scan_reports WHERE id = ?", (report_id,)).fetchone()
    return {"report": row_to_scan(row)}


@app.get("/scan-reports")
async def get_scan_reports(limit: int = Query(default=10, ge=1, le=50), user: dict[str, str] = Depends(require_admin)):
    with db_session() as connection:
        rows = connection.execute("SELECT * FROM scan_reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"scan_reports": [row_to_scan(row) for row in rows]}


@app.post("/assessment-reports", dependencies=[Depends(require_same_origin_request)])
async def create_assessment_report(data: AssessmentReportCreate, user: dict[str, str] = Depends(require_admin)):
    safe_checks = []
    for check in data.checks[:60]:
        if not isinstance(check, dict):
            continue
        safe = {}
        for key in ("name", "status", "detail"):
            value = check.get(key)
            if isinstance(value, str):
                safe[key] = value[:240]
        if safe:
            safe_checks.append(safe)
    created_at = now_iso()
    with db_session() as connection:
        cursor = connection.execute(
            """INSERT INTO assessment_reports (created_at, name, status, passed, failed, checks_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (created_at, data.name, data.status, data.passed, data.failed, json.dumps(safe_checks, separators=(",", ":"))),
        )
        report_id = cursor.lastrowid
        row = connection.execute("SELECT * FROM assessment_reports WHERE id = ?", (report_id,)).fetchone()
    store_event(EventCreate(event_type="security.assessment.completed", source="security_assessment",
        severity="INFO" if data.failed == 0 else "WARNING", actor=user["username"],
        details={"assessment": data.name, "passed": data.passed, "failed": data.failed, "result": data.status}))
    return {"report": row_to_assessment(row)}


@app.get("/assessment-reports")
async def get_assessment_reports(limit: int = Query(default=10, ge=1, le=50), user: dict[str, str] = Depends(require_admin)):
    with db_session() as connection:
        rows = connection.execute("SELECT * FROM assessment_reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"assessment_reports": [row_to_assessment(row) for row in rows]}


@app.get("/report")
async def export_security_report(user: dict[str, str] = Depends(require_admin)):
    summary_data = await summary(user)
    events_data = await get_events(limit=100, severity=None, user=user)
    scans_data = await get_scan_reports(limit=20, user=user)
    assessments_data = await get_assessment_reports(limit=20, user=user)
    return {
        "product": "CloudGuard AI", "version": "2.0.0", "generated_at": now_iso(),
        "scope": "Local educational security assessment; not a production certification.",
        "summary": summary_data, "events": events_data["events"],
        "scan_reports": scans_data["scan_reports"], "assessment_reports": assessments_data["assessment_reports"],
        "security_controls": [
            {"control": "Loopback-only edge proxy is the only host-published service; app gateway remains internal", "status": "configured"},
            {"control": "Backend Docker network is internal", "status": "configured"},
            {"control": "Argon2 password hashing and signed JWT HttpOnly session cookie", "status": "configured"},
            {"control": "Nginx request throttling on login and AI routes", "status": "configured"},
            {"control": "Non-root application containers and read-only root filesystems", "status": "configured"},
            {"control": "Internal service-token checks and gateway hiding of internal monitor routes", "status": "configured"},
            {"control": "Trivy image scanning", "status": "operator-run; see scan reports"},
            {"control": "Security regression checks", "status": "operator-run; see assessment reports"},
        ],
        "baseline_comparison": [
            {"area": "Network exposure", "original": "Auth, AI, and logger ports were published directly", "hardened": "Only loopback-bound edge proxy is published; app gateway and backend services remain internal", "evidence": "Compose configuration"},
            {"area": "Credentials", "original": "Hard-coded plaintext demo passwords", "hardened": "Random bootstrap password and Argon2 hash", "evidence": "Auth implementation and regression tests"},
            {"area": "Session token", "original": "Base64-encoded username", "hardened": "Signed expiring JWT in HttpOnly/SameSite cookie", "evidence": "Auth implementation and cookie checks"},
            {"area": "AI access", "original": "Unauthenticated chat route and no rate limit", "hardened": "Authenticated AI route and Nginx throttling", "evidence": "Regression suite and gateway configuration"},
            {"area": "Logging", "original": "Raw prompt/response data in a public in-memory list", "hardened": "Bounded event metadata and separate per-user local chat storage", "evidence": "Monitor implementation and tests"},
            {"area": "Service trust", "original": "No internal service authentication", "hardened": "Internal service token and hidden gateway routes", "evidence": "Internal route tests"},
            {"area": "Container runtime", "original": "Debug mode and no runtime hardening", "hardened": "Non-root, read-only filesystem, dropped capabilities", "evidence": "Dockerfiles and Compose configuration"},
            {"area": "Image assessment", "original": "Trivy was a plan only", "hardened": "Trivy archive scanning and saved reports", "evidence": "Actual scan reports when run"},
        ],
        "limitations": [
            "AI output is advisory and may be incorrect.",
            "Synthetic lab events are not real attacks.",
            "A clean scan does not prove the application is secure.",
            "This report is not a compliance certification or penetration-test attestation.",
        ],
    }
