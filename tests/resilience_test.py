#!/usr/bin/env python3
"""Run a small, non-destructive service-health and Compose resilience check."""
from __future__ import annotations

import concurrent.futures
import getpass
import http.cookiejar
import json
import os
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = os.getenv("CLOUDGUARD_URL", "http://127.0.0.1:8080").rstrip("/")


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    path = ROOT / ".env"
    if not path.exists():
        raise RuntimeError(".env is missing. Run python3 scripts/setup.py first.")
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def compose_config() -> dict:
    result = subprocess.run(
        ["docker", "compose", "config", "--format", "json"], cwd=ROOT,
        capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "docker compose config failed")[-1200:])
    return json.loads(result.stdout)


def request_health(path: str) -> tuple[int, float]:
    request = urllib.request.Request(BASE_URL + path, headers={"Accept": "application/json"})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            response.read(1024)
            return response.status, (time.perf_counter() - started) * 1000
    except urllib.error.HTTPError as error:
        return error.code, (time.perf_counter() - started) * 1000
    except (urllib.error.URLError, TimeoutError):
        return 0, (time.perf_counter() - started) * 1000


def save_report(username: str, password: str, checks: list[dict[str, str]]) -> None:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    login_data = json.dumps({"username": username, "password": password}).encode()
    login_request = urllib.request.Request(
        BASE_URL + "/api/auth/login", data=login_data,
        headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}, method="POST",
    )
    with opener.open(login_request, timeout=10) as response:
        login = json.loads(response.read().decode())
    if not login.get("authenticated"):
        raise RuntimeError("Administrator authentication failed.")
    passed = sum(1 for item in checks if item["status"] == "passed")
    failed = len(checks) - passed
    payload = json.dumps({
        "name": "CloudGuard AI Lightweight Resilience Check",
        "status": "passed" if failed == 0 else "failed",
        "passed": passed, "failed": failed, "checks": checks,
    }).encode()
    request = urllib.request.Request(
        BASE_URL + "/api/monitor/assessment-reports", data=payload,
        headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}, method="POST",
    )
    with opener.open(request, timeout=15) as response:
        response.read()


def main() -> int:
    checks: list[dict[str, str]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        status = "passed" if ok else "failed"
        checks.append({"name": name, "status": status, "detail": detail[:240]})
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")

    try:
        env = read_env()
        print("CloudGuard AI - lightweight resilience check")
        print("This test sends a small number of health requests. It does not stop containers or generate attack traffic.\n")

        config = compose_config()
        services = config.get("services", {})
        published = []
        for service_name, service in services.items():
            for port in service.get("ports", []):
                published.append((service_name, str(port.get("host_ip", "")), str(port.get("published", ""))))
        only_edge = len(published) == 1 and published[0][0] == "edge" and published[0][1] == "127.0.0.1" and published[0][2] == "8080"
        record("Only loopback edge proxy publishes a host port", only_edge, str(published))
        healthchecks = all(bool(service.get("healthcheck")) for service in services.values()) and len(services) == 5
        record("All five services define health checks", healthchecks, f"{sum(bool(service.get('healthcheck')) for service in services.values())}/{len(services)} configured")
        restart_policies = all(service.get("restart") == "unless-stopped" for service in services.values()) and len(services) == 5
        record("Services have automatic restart policy", restart_policies, "unless-stopped" if restart_policies else "One or more services are missing the expected policy")
        networks = config.get("networks", {})
        backend = networks.get("backend", {})
        frontend = networks.get("frontend", {})
        host_ingress = networks.get("host_ingress", {})
        record("Backend network is internal", backend.get("internal") is True, f"internal={backend.get('internal')}")
        record("Application frontend network is internal", frontend.get("internal") is True, f"internal={frontend.get('internal')}")
        def network_names(service_name: str) -> set[str]:
            configured = services.get(service_name, {}).get("networks", {})
            return set(configured if isinstance(configured, list) else configured.keys())

        edge_networks = services.get("edge", {}).get("networks", {})
        edge_ingress = edge_networks.get("host_ingress", {}) if isinstance(edge_networks, dict) else {}
        edge_ingress_ok = "host_ingress" in network_names("edge") and host_ingress.get("internal") is not True and edge_ingress.get("gw_priority") == 1 and "host_ingress" not in network_names("gateway")
        record("Only edge proxy uses the non-internal host-ingress network", edge_ingress_ok, str({"edge": sorted(network_names("edge")), "gateway": sorted(network_names("gateway")), "internal": host_ingress.get("internal"), "gw_priority": edge_ingress.get("gw_priority")}))
        ai_network_config = services.get("ai", {}).get("networks", {})
        egress_config = ai_network_config.get("egress", {}) if isinstance(ai_network_config, dict) else {}
        egress_only_ai = "egress" in network_names("ai") and all("egress" not in network_names(name) for name in ("edge", "gateway", "auth", "monitor")) and egress_config.get("gw_priority") == 1
        record("Only AI service has application egress network", egress_only_ai, str({name: sorted(network_names(name)) for name in services}))

        paths = [
            "/api/health", "/api/auth/health", "/api/monitor/health",
            "/api/health", "/api/auth/health", "/api/monitor/health",
            "/api/health", "/api/auth/health", "/api/monitor/health",
            "/api/health", "/api/monitor/health", "/api/ai/health",
        ]
        request_count = len(paths)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(request_health, paths))
        statuses = [status for status, _ in results]
        latencies = sorted(latency for _, latency in results)
        successful = sum(1 for status in statuses if status == 200)
        p95_index = min(len(latencies) - 1, max(0, int(len(latencies) * 0.95) - 1))
        p95 = latencies[p95_index]
        record("Health endpoints available under light concurrency", successful == request_count, f"{successful}/{request_count} HTTP 200 responses")
        record("Health endpoint p95 latency", p95 < 2000, f"{p95:.1f} ms (target < 2000 ms)")

        username = env.get("BOOTSTRAP_ADMIN_USERNAME", "admin")
        password = getpass.getpass(f"CloudGuard password for {username} (to save results): ")
        save_report(username, password, checks)
        passed = sum(1 for item in checks if item["status"] == "passed")
        failed = len(checks) - passed
        print(f"\nSaved resilience assessment: {passed} passed, {failed} failed.")
        return 0 if failed == 0 else 1
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
