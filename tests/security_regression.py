#!/usr/bin/env python3
"""Run a safe, authenticated security regression suite against a local CloudGuard stack."""
from __future__ import annotations

import getpass
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = os.getenv("CLOUDGUARD_URL", "http://127.0.0.1:8080").rstrip("/")


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    path = ROOT / ".env"
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def make_request(opener, path: str, method: str = "GET", body: dict | None = None, extra_headers: dict | None = None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    try:
        with opener.open(request, timeout=12) as response:
            raw = response.read()
            return response.status, response.headers, json.loads(raw.decode()) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            payload = json.loads(raw.decode()) if raw else {}
        except json.JSONDecodeError:
            payload = {}
        return exc.code, exc.headers, payload


def main() -> int:
    checks: list[dict[str, str]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        status = "passed" if ok else "failed"
        checks.append({"name": name, "status": status, "detail": detail[:240]})
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")

    try:
        env = read_env()
        print("CloudGuard AI - security regression suite")
        print("These checks target only the local CloudGuard application.\n")
        plain = urllib.request.build_opener()

        status, headers, health = make_request(plain, "/api/health")
        record("Gateway health", status == 200 and health.get("service") == "gateway", f"HTTP {status}")
        required_headers = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
        missing_headers = [name for name in required_headers if not headers.get(name)]
        record("Security response headers", not missing_headers, "All required headers present" if not missing_headers else "Missing: " + ", ".join(missing_headers))

        status, _, _ = make_request(plain, "/api/monitor/events")
        record("Anonymous event access denied", status == 401, f"HTTP {status}; expected 401")
        status, _, _ = make_request(plain, "/api/monitor/internal/recent-events")
        record("Internal service routes hidden by gateway", status == 404, f"HTTP {status}; expected 404 at the public gateway")
        status, _, _ = make_request(plain, "/api/auth/logout", "POST", {}, {})
        record("State-changing request requires CSRF header", status == 403, f"HTTP {status}; expected 403")

        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        username = env.get("BOOTSTRAP_ADMIN_USERNAME", "admin")
        password = getpass.getpass(f"CloudGuard password for {username}: ")
        status, _, login = make_request(opener, "/api/auth/login", "POST", {"username": username, "password": password}, {"X-Requested-With": "XMLHttpRequest"})
        record("Administrator authentication", status == 200 and login.get("authenticated") is True, f"HTTP {status}")
        if status != 200:
            raise RuntimeError("Login failed; remaining authenticated checks cannot run.")

        session_cookie = next((cookie for cookie in cookie_jar if cookie.name == "cloudguard_access"), None)
        cookie_ok = bool(session_cookie and session_cookie.has_nonstandard_attr("HttpOnly") and session_cookie.get_nonstandard_attr("SameSite", "").lower() == "strict")
        record("Session cookie flags", cookie_ok, "HttpOnly and SameSite=Strict" if cookie_ok else "Expected HttpOnly and SameSite=Strict cookie")

        status, _, session = make_request(opener, "/api/auth/me")
        record("Authenticated session validation", status == 200 and session.get("user", {}).get("username") == username, f"HTTP {status}")

        status, _, ai_health = make_request(opener, "/api/ai/health")
        ai_safe = status == 200 and isinstance(ai_health.get("provider_configured"), bool) and "api_key" not in ai_health
        record("AI provider status does not expose API key", ai_safe, f"HTTP {status}")

        status, _, history = make_request(opener, "/api/ai/history")
        record("Persistent AI history endpoint", status == 200 and history.get("storage") == "sqlite", f"HTTP {status}; storage={history.get('storage', 'unknown')}")

        status, _, summary = make_request(opener, "/api/monitor/summary")
        counts_match = status == 200 and summary.get("critical", 0) + summary.get("warnings", 0) + summary.get("info", 0) == summary.get("total_events", -1)
        record("Dashboard 24-hour counters are internally consistent", counts_match, f"HTTP {status}; total_24h={summary.get('total_events', 'n/a')}")

        status, _, reports = make_request(opener, "/api/monitor/scan-reports")
        record("Container scan report endpoint", status == 200 and "scan_reports" in reports, f"HTTP {status}")
        status, _, export = make_request(opener, "/api/monitor/report")
        record("Security report export endpoint", status == 200 and export.get("product") == "CloudGuard AI", f"HTTP {status}")

        status, _, simulation = make_request(opener, "/api/monitor/simulate", "POST", {"scenario": "unauthorized_api"}, {"X-Requested-With": "XMLHttpRequest"})
        created_id = simulation.get("event", {}).get("id") if status == 200 else None
        record("Safe synthetic scenario creation", status == 200 and simulation.get("simulated") is True, f"HTTP {status}")
        status, _, events = make_request(opener, "/api/monitor/events?limit=100")
        persisted = status == 200 and any(event.get("id") == created_id for event in events.get("events", []))
        record("Event persistence and retrieval", persisted, f"HTTP {status}; event_id={created_id}")

        passed = sum(1 for item in checks if item["status"] == "passed")
        failed = len(checks) - passed
        report_status = "passed" if failed == 0 else "failed"
        payload = {"name": "CloudGuard AI Security Regression Suite", "status": report_status,
                   "passed": passed, "failed": failed, "checks": checks}
        status, _, saved = make_request(opener, "/api/monitor/assessment-reports", "POST", payload, {"X-Requested-With": "XMLHttpRequest"})
        record("Assessment result saved to dashboard", status == 200 and "report" in saved, f"HTTP {status}")
        print(f"\nResult: {passed} passed, {failed} failed (assessment upload status: HTTP {status}).")
        return 0 if failed == 0 and status == 200 else 1
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
