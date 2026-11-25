#!/usr/bin/env python3
"""End-to-end checks for a running local CloudGuard AI stack."""
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
    env_path = ROOT / ".env"
    if not env_path.exists():
        raise RuntimeError(".env is missing. Run python3 scripts/setup.py first.")
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def request(opener: urllib.request.OpenerDirector, path: str, method: str = "GET", body: dict | None = None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        headers["X-Requested-With"] = "XMLHttpRequest"
    req = urllib.request.Request(BASE_URL + path, data=data, headers=headers, method=method)
    with opener.open(req, timeout=8) as response:
        raw = response.read()
        return response.status, json.loads(raw.decode("utf-8")) if raw else {}


def expect_unauthorized(path: str) -> None:
    req = urllib.request.Request(BASE_URL + path, headers={"Accept": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=8)
    except urllib.error.HTTPError as error:
        if error.code == 401:
            print(f"PASS protected route rejects anonymous request: {path}")
            return
        raise RuntimeError(f"Expected 401 from {path}, got {error.code}") from error
    raise RuntimeError(f"Expected 401 from {path}, but request succeeded")


def main() -> int:
    try:
        env = read_env()
        print("CloudGuard AI smoke test")
        plain_opener = urllib.request.build_opener()
        status, gateway = request(plain_opener, "/api/health")
        assert status == 200 and gateway.get("service") == "gateway"
        print("PASS gateway health")

        expect_unauthorized("/api/monitor/events")

        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        username = env.get("BOOTSTRAP_ADMIN_USERNAME", "admin")
        password = getpass.getpass(f"CloudGuard password for {username}: ")
        if not password:
            raise RuntimeError("A password is required for the authenticated smoke checks.")
        status, login = request(opener, "/api/auth/login", "POST", {"username": username, "password": password})
        assert status == 200 and login.get("authenticated") is True
        print("PASS administrator login")

        status, session = request(opener, "/api/auth/me")
        assert status == 200 and session.get("user", {}).get("username") == username
        print("PASS HttpOnly session validation")

        status, summary = request(opener, "/api/monitor/summary")
        assert status == 200 and "total_events" in summary
        print("PASS protected monitoring summary")

        status, simulated = request(opener, "/api/monitor/simulate", "POST", {"scenario": "unauthorized_api"})
        assert status == 200 and simulated.get("simulated") is True
        print("PASS safe synthetic event creation")

        status, events = request(opener, "/api/monitor/events?limit=10")
        assert status == 200 and any(item.get("event_type") == "api.access_denied.simulated" for item in events.get("events", []))
        print("PASS event persistence and retrieval")

        status, ai_health = request(opener, "/api/ai/health")
        assert status == 200 and ai_health.get("service") == "ai"
        if ai_health.get("provider_configured"):
            print(f"INFO NVIDIA provider configured: {ai_health.get('model')}; live inference not called by this test")
        else:
            print("INFO NVIDIA_API_KEY is empty; AI inference is skipped")

        print("\nAll smoke checks passed.")
        return 0
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
