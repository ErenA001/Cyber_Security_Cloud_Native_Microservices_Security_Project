#!/usr/bin/env python3
"""Check local prerequisites, configuration, Compose validity and gateway health."""
from __future__ import annotations

import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], timeout: int = 20) -> tuple[bool, str]:
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return False, f"{command[0]} is not installed or not on PATH"
    except subprocess.TimeoutExpired:
        return False, f"{command[0]} timed out"
    output = (result.stdout or result.stderr).strip()
    return result.returncode == 0, output if output else f"exit code {result.returncode}"


def main() -> int:
    checks: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))
        print(f"{'PASS' if ok else 'CHECK'}  {name}: {detail}")

    env_path = ROOT / ".env"
    add("Project environment file", env_path.exists(), str(env_path.name) if env_path.exists() else "Run python3 scripts/setup.py")
    if env_path.exists():
        try:
            mode = env_path.stat().st_mode & 0o777
            add(".env file permissions", mode & 0o077 == 0, oct(mode))
            env_values = {}
            for raw in env_path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_values[key.strip()] = value.strip()
            add("Generated application secrets", all(env_values.get(key) and "GENERATE_WITH_SETUP_SCRIPT" not in env_values.get(key, "") for key in ("JWT_SECRET_KEY", "SERVICE_TOKEN", "BOOTSTRAP_ADMIN_PASSWORD")), "Required values present" if all(env_values.get(key) and "GENERATE_WITH_SETUP_SCRIPT" not in env_values.get(key, "") for key in ("JWT_SECRET_KEY", "SERVICE_TOKEN", "BOOTSTRAP_ADMIN_PASSWORD")) else "Run python3 scripts/setup.py")
            add("NVIDIA API key", bool(env_values.get("NVIDIA_API_KEY")), "Configured" if env_values.get("NVIDIA_API_KEY") else "AI chat needs NVIDIA_API_KEY")
        except OSError as error:
            add("Read .env", False, str(error))

    ok, detail = run(["docker", "--version"])
    add("Docker CLI", ok, detail)
    ok_compose, detail_compose = run(["docker", "compose", "version"])
    add("Docker Compose", ok_compose, detail_compose)
    if ok_compose:
        ok_config, detail_config = run(["docker", "compose", "config", "--quiet"])
        add("Compose configuration", ok_config, detail_config or ("Valid" if ok_config else "Invalid"))
        ok_ps, detail_ps = run(["docker", "compose", "ps", "--format", "table {{.Service}} {{.State}} {{.Health}}"])
        services_present = ok_ps and all(name in detail_ps for name in ("edge", "gateway", "auth", "ai", "monitor"))
        add("Compose services", services_present, detail_ps or ("No running services" if not ok_ps else "No services listed"))
        ok_port, detail_port = run(["docker", "compose", "port", "edge", "8080"])
        port_ok = ok_port and detail_port.strip() == "127.0.0.1:8080"
        add("Loopback-only edge port publication", port_ok, detail_port or "No host port published")

    try:
        request = urllib.request.Request("http://127.0.0.1:8080/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read(500).decode(errors="replace")
            add("CloudGuard gateway", response.status == 200 and '"service":"gateway"' in body.replace(" ", ""), f"HTTP {response.status}")
    except (urllib.error.URLError, TimeoutError) as error:
        add("CloudGuard gateway", False, f"Not reachable: {error}")

    failed = sum(1 for _, ok, _ in checks if not ok)
    print(f"\n{len(checks) - failed}/{len(checks)} checks passed or confirmed.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
