from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TEMP_ROOT = tempfile.TemporaryDirectory(prefix="cloudguard-tests-")
DATA_DIR = Path(TEMP_ROOT.name)
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key-that-is-at-least-thirty-two-bytes-long"
os.environ["SERVICE_TOKEN"] = "test-internal-service-token"
os.environ["MONITOR_INTERNAL_URL"] = "http://127.0.0.1:9/internal/events"
os.environ["BOOTSTRAP_ADMIN_USERNAME"] = "admin"
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = "Test-Admin-Password-2026!"
os.environ["AUTH_DATABASE_PATH"] = str(DATA_DIR / "auth.db")
os.environ["MONITOR_DATABASE_PATH"] = str(DATA_DIR / "events.db")
os.environ["AI_DATABASE_PATH"] = str(DATA_DIR / "ai.db")
os.environ["NVIDIA_API_KEY"] = "test-key-not-used"

from fastapi.testclient import TestClient

from services.auth.app import app as auth_app
from services.monitor.app import app as monitor_app
from services.ai import app as ai_module
from services.ai.app import app as ai_app
from scripts.scan_local_images import redact_secret_matches


async def fake_nvidia(messages, max_tokens=900):
    return {"reply": "Test analysis response", "model": "test-model", "usage": {"total_tokens": 12}}


async def fake_internal_get(url, limit):
    if "scan-reports" in url:
        return {"scan_reports": [{"image": "cloudguard-ai/api:test", "summary": {"critical": 1}}]}
    return {"events": [{"id": 1, "event_type": "container.scan.completed", "severity": "CRITICAL", "source": "container_scanner", "details": {"critical": 1}}]}


class CloudGuardCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth_client = TestClient(auth_app)
        cls.monitor_client = TestClient(monitor_app)
        cls.ai_client = TestClient(ai_app)
        cls.auth_client.__enter__()
        cls.monitor_client.__enter__()
        cls.ai_client.__enter__()
        response = cls.auth_client.post(
            "/login",
            json={"username": "admin", "password": "Test-Admin-Password-2026!"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        if response.status_code != 200:
            raise RuntimeError(f"Test login failed: {response.text}")
        token = response.cookies.get("cloudguard_access")
        set_cookie = response.headers.get("set-cookie", "")
        if "HttpOnly" not in set_cookie or "SameSite=strict" not in set_cookie:
            raise RuntimeError(f"Session cookie flags missing: {set_cookie}")
        cls.monitor_client.cookies.set("cloudguard_access", token)
        cls.ai_client.cookies.set("cloudguard_access", token)

    @classmethod
    def tearDownClass(cls):
        cls.ai_client.__exit__(None, None, None)
        cls.monitor_client.__exit__(None, None, None)
        cls.auth_client.__exit__(None, None, None)
        TEMP_ROOT.cleanup()

    def test_anonymous_routes_are_protected(self):
        anonymous = TestClient(monitor_app)
        with anonymous:
            self.assertEqual(anonymous.get("/events").status_code, 401)

    def test_summary_counts_and_event_persistence(self):
        response = self.monitor_client.post(
            "/simulate", json={"scenario": "unauthorized_api"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        event_id = response.json()["event"]["id"]
        events = self.monitor_client.get("/events?limit=100")
        self.assertEqual(events.status_code, 200)
        self.assertTrue(any(event["id"] == event_id for event in events.json()["events"]))
        summary = self.monitor_client.get("/summary")
        self.assertEqual(summary.status_code, 200)
        data = summary.json()
        self.assertEqual(data["critical"] + data["warnings"] + data["info"], data["total_events"])
        self.assertGreaterEqual(data["all_time_events"], data["total_events"])

    def test_csrf_and_origin_checks_reject_invalid_state_changes(self):
        no_header = self.monitor_client.post("/simulate", json={"scenario": "unauthorized_api"})
        self.assertEqual(no_header.status_code, 403)
        wrong_origin = self.monitor_client.post(
            "/simulate", json={"scenario": "unauthorized_api"},
            headers={"X-Requested-With": "XMLHttpRequest", "Origin": "https://attacker.invalid"},
        )
        self.assertEqual(wrong_origin.status_code, 403)
        wrong_scheme = self.monitor_client.post(
            "/simulate", json={"scenario": "unauthorized_api"},
            headers={"X-Requested-With": "XMLHttpRequest", "Origin": "https://testserver"},
        )
        self.assertEqual(wrong_scheme.status_code, 403)

    def test_internal_service_token_is_required(self):
        anonymous = TestClient(monitor_app)
        with anonymous:
            self.assertEqual(anonymous.get("/internal/recent-events").status_code, 401)
        response = self.monitor_client.get("/internal/recent-events", headers={"X-Service-Token": "test-internal-service-token"})
        self.assertEqual(response.status_code, 200)

    def test_scan_and_assessment_reports_are_persisted(self):
        headers = {"X-Requested-With": "XMLHttpRequest"}
        scan = self.monitor_client.post("/scan-reports", headers=headers, json={
            "image": "cloudguard-ai/api:test", "image_id": "sha256:test-image", "scanner": "Trivy", "scanner_version": "0.58.2",
            "scanner_metadata": {"version": "0.58.2", "vulnerability_db_updated_at": "2026-11-25T00:00:00Z", "api_key": "must be dropped"},
            "scan_status": "completed", "summary": {"critical": 1, "high": 2, "medium": 3, "vulnerabilities": 6},
            "findings": [{"id": "CVE-TEST", "package": "demo", "severity": "CRITICAL", "title": "Test finding", "ignored": "must be dropped"}],
        })
        self.assertEqual(scan.status_code, 200, scan.text)
        reports = self.monitor_client.get("/scan-reports")
        self.assertEqual(reports.status_code, 200)
        self.assertEqual(reports.json()["scan_reports"][0]["summary"]["critical"], 1)
        self.assertEqual(reports.json()["scan_reports"][0]["image_id"], "sha256:test-image")
        self.assertEqual(reports.json()["scan_reports"][0]["scanner_metadata"]["version"], "0.58.2")
        self.assertNotIn("api_key", reports.json()["scan_reports"][0]["scanner_metadata"])
        self.assertNotIn("ignored", reports.json()["scan_reports"][0]["findings"][0])

        assessment = self.monitor_client.post("/assessment-reports", headers=headers, json={
            "name": "Unit test suite", "status": "passed", "passed": 3, "failed": 0,
            "checks": [{"name": "JWT", "status": "passed", "detail": "valid", "secret": "drop"}],
        })
        self.assertEqual(assessment.status_code, 200, assessment.text)
        self.assertEqual(self.monitor_client.get("/assessment-reports").json()["assessment_reports"][0]["passed"], 3)

    def test_trivy_raw_report_redacts_secret_matches(self):
        raw = {"Results": [{"Secrets": [{"RuleID": "test-rule", "Match": "demo-secret", "Code": "line with secret", "Severity": "HIGH"}]}]}
        redacted = redact_secret_matches(raw)
        secret = redacted["Results"][0]["Secrets"][0]
        self.assertEqual(secret["Match"], "[REDACTED]")
        self.assertEqual(secret["Code"], "[REDACTED]")
        self.assertEqual(secret["RuleID"], "test-rule")

    def test_report_export_includes_evidence_and_limits(self):
        response = self.monitor_client.get("/report")
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["product"], "CloudGuard AI")
        self.assertIn("security_controls", data)
        self.assertIn("baseline_comparison", data)
        self.assertIn("limitations", data)

    def test_ai_chat_history_persists_in_sqlite(self):
        headers = {"X-Requested-With": "XMLHttpRequest"}
        with patch.object(ai_module, "call_nvidia", new=fake_nvidia):
            response = self.ai_client.post("/chat", headers=headers, json={"message": "Explain JWT security."})
        self.assertEqual(response.status_code, 200, response.text)
        history = self.ai_client.get("/history")
        self.assertEqual(history.status_code, 200)
        messages = history.json()["messages"]
        self.assertEqual(messages[-2]["role"], "user")
        self.assertEqual(messages[-1]["role"], "assistant")
        self.assertEqual(messages[-1]["content"], "Test analysis response")
        self.assertEqual(history.json()["storage"], "sqlite")

    def test_ai_analysis_includes_scan_context_and_persists(self):
        headers = {"X-Requested-With": "XMLHttpRequest"}
        with patch.object(ai_module, "call_nvidia", new=fake_nvidia), patch.object(ai_module, "internal_get", new=fake_internal_get):
            response = self.ai_client.post("/analyze-events", headers=headers, json={})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["events_analyzed"], 1)
        self.assertEqual(response.json()["scans_analyzed"], 1)
        history = self.ai_client.get("/history").json()["messages"]
        self.assertEqual(history[-1]["content"], "Test analysis response")

    def test_password_change_invalidates_session_cookie(self):
        response = self.auth_client.post(
            "/change-password",
            headers={"X-Requested-With": "XMLHttpRequest"},
            json={"current_password": "Test-Admin-Password-2026!", "new_password": "New-Test-Admin-Password-2026!"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("cloudguard_access", response.headers.get("set-cookie", ""))
        login = self.auth_client.post(
            "/login", headers={"X-Requested-With": "XMLHttpRequest"},
            json={"username": "admin", "password": "New-Test-Admin-Password-2026!"},
        )
        self.assertEqual(login.status_code, 200, login.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
