#!/usr/bin/env python3
"""Scan local Docker images with Trivy without mounting the Docker socket."""
from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "http://127.0.0.1:8080"
DEFAULT_IMAGES = [
    "cloudguard-ai/edge:local",
    "cloudguard-ai/gateway:local",
    "cloudguard-ai/auth:local",
    "cloudguard-ai/ai:local",
    "cloudguard-ai/monitor:local",
]
TRIVY_IMAGE_DEFAULT = "aquasec/trivy:0.58.2"


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


def run_command(command: list[str], timeout: int = 900) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required command not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out after {timeout} seconds: {command[0]}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "No command output").strip()[-1800:]
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(command[:4])}\n{detail}")
    return result


def severity_counts(results: list[dict]) -> tuple[dict[str, int], list[dict[str, object]]]:
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "unknown")}
    counts.update({"vulnerabilities": 0, "misconfigurations": 0, "secrets": 0})
    findings: list[dict[str, object]] = []
    for result in results:
        target = str(result.get("Target") or "")[:240]
        result_class = str(result.get("Class") or "")[:80]
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("Severity") or "UNKNOWN").lower()
            counts[severity if severity in counts else "unknown"] += 1
            counts["vulnerabilities"] += 1
            findings.append({
                "id": item.get("VulnerabilityID", ""),
                "package": item.get("PkgName", ""),
                "installed_version": item.get("InstalledVersion", ""),
                "fixed_version": item.get("FixedVersion", ""),
                "severity": severity.upper(),
                "title": item.get("Title", ""),
                "target": target,
                "class": result_class,
                "type": item.get("PkgIdentifier", {}).get("PURL", "") if isinstance(item.get("PkgIdentifier"), dict) else "",
                "primary_url": item.get("PrimaryURL", ""),
            })
        for item in result.get("Misconfigurations") or []:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("Severity") or "UNKNOWN").lower()
            counts[severity if severity in counts else "unknown"] += 1
            counts["misconfigurations"] += 1
            findings.append({
                "id": item.get("ID", ""), "severity": severity.upper(),
                "title": item.get("Title", ""), "target": target,
                "class": "misconfiguration", "message": item.get("Message", ""),
            })
        for item in result.get("Secrets") or []:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("Severity") or "UNKNOWN").lower()
            counts[severity if severity in counts else "unknown"] += 1
            counts["secrets"] += 1
            findings.append({
                "id": item.get("RuleID", ""), "severity": severity.upper(),
                "title": item.get("Title", "Secret finding"), "target": target,
                "class": "secret", "category": item.get("Category", ""),
                "start_line": item.get("StartLine", 0),
            })
    findings.sort(key=lambda item: (0 if item.get("severity") == "CRITICAL" else 1 if item.get("severity") == "HIGH" else 2, str(item.get("id", ""))))
    return counts, findings[:100]


def authenticated_opener(username: str, password: str) -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    payload = json.dumps({"username": username, "password": password}).encode()
    request = urllib.request.Request(
        BASE_URL + "/api/auth/login", data=payload,
        headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}, method="POST",
    )
    try:
        with opener.open(request, timeout=12) as response:
            data = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Login failed with HTTP {exc.code}. Check the account password.") from exc
    if not data.get("authenticated"):
        raise RuntimeError("Login did not return an authenticated session.")
    return opener


def upload_report(opener: urllib.request.OpenerDirector, report: dict[str, object]) -> None:
    payload = json.dumps(report).encode()
    request = urllib.request.Request(
        BASE_URL + "/api/monitor/scan-reports", data=payload,
        headers={"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"}, method="POST",
    )
    try:
        with opener.open(request, timeout=20) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        raise RuntimeError(f"Could not save scan report (HTTP {exc.code}): {detail}") from exc


def redact_secret_matches(report: dict[str, object]) -> dict[str, object]:
    """Remove matched secret values and source snippets before saving a local raw report."""
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for secret in result.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            for key in ("Match", "Code", "Raw", "Secret", "Value"):
                if key in secret:
                    secret[key] = "[REDACTED]"
    return report


def get_trivy_metadata(trivy_image: str, cache_volume: str) -> dict[str, object]:
    command = [
        "docker", "run", "--rm", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--volume", f"{cache_volume}:/root/.cache/trivy", trivy_image, "version", "--format", "json",
    ]
    try:
        result = run_command(command, timeout=60)
        data = json.loads(result)
    except Exception:
        return {"version": trivy_image.rsplit(":", 1)[-1]}
    db = data.get("VulnerabilityDB") or data.get("VulnerabilityDBInfo") or {}
    if not isinstance(db, dict):
        db = {}
    return {
        "version": str(data.get("Version") or trivy_image.rsplit(":", 1)[-1]),
        "vulnerability_db_version": db.get("Version"),
        "vulnerability_db_updated_at": db.get("UpdatedAt"),
        "vulnerability_db_next_update": db.get("NextUpdate"),
        "vulnerability_db_downloaded_at": db.get("DownloadedAt"),
    }


def scan_one(image: str, trivy_image: str, cache_volume: str) -> tuple[dict[str, object], dict[str, object]]:
    image_id = run_command(["docker", "image", "inspect", "--format", "{{.Id}}", image], timeout=30)
    with tempfile.TemporaryDirectory(prefix=".cloudguard-trivy-", dir=ROOT) as temp_dir:
        archive = Path(temp_dir) / "image.tar"
        run_command(["docker", "image", "save", "--output", str(archive), image], timeout=180)
        scan_command = [
            "docker", "run", "--rm", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
            "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
            "--mount", f"type=bind,source={temp_dir},target=/scan,readonly",
            "--volume", f"{cache_volume}:/root/.cache/trivy",
            trivy_image, "image", "--input", "/scan/image.tar",
            "--format", "json", "--scanners", "vuln,misconfig,secret",
            "--timeout", "10m", "--no-progress", "--exit-code", "0",
        ]
        result = run_command(scan_command, timeout=900)
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Trivy returned invalid JSON for {image}.") from exc
    counts, findings = severity_counts(data.get("Results") or [])
    metadata = get_trivy_metadata(trivy_image, cache_volume)
    report = {
        "image": image, "image_id": image_id,
        "scanner": "Trivy", "scanner_version": trivy_image.rsplit(":", 1)[-1],
        "scanner_metadata": metadata,
        "scan_status": "completed", "summary": counts, "findings": findings,
    }
    return report, redact_secret_matches(data)


def save_raw_report(image: str, image_id: str, scanner_version: str, scanner_metadata: dict[str, object], report_data: dict[str, object]) -> Path:
    output_dir = ROOT / "reports" / "trivy"
    output_dir.mkdir(parents=True, exist_ok=True)
    scanned_at = datetime.now(timezone.utc)
    timestamp = scanned_at.strftime("%Y%m%dT%H%M%S%fZ")
    safe_tag = re.sub(r"[^a-zA-Z0-9_.-]+", "_", image)[:100]
    path = output_dir / f"{timestamp}_{safe_tag}.json"
    document = {
        "image": image, "image_id": image_id, "scanned_at": scanned_at.isoformat(),
        "scanner": "Trivy", "scanner_version": scanner_version, "scanner_metadata": scanner_metadata,
        "secret_matches_redacted": True, "report": report_data,
    }
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def main() -> int:
    global BASE_URL
    parser = argparse.ArgumentParser(description="Scan local CloudGuard images and save results to the dashboard.")
    parser.add_argument("--images", default=",".join(DEFAULT_IMAGES), help="Comma-separated local Docker image tags.")
    parser.add_argument("--trivy-image", default=os.getenv("TRIVY_IMAGE", TRIVY_IMAGE_DEFAULT))
    parser.add_argument("--url", default=BASE_URL, help="CloudGuard URL (default: local gateway).")
    args = parser.parse_args()
    BASE_URL = args.url.rstrip("/")

    try:
        env = read_env()
        print("CloudGuard AI - local Docker image security scan")
        print("Scanner runs in an isolated container. The Docker socket is NOT mounted into Trivy.\n")
        username = env.get("BOOTSTRAP_ADMIN_USERNAME", "admin")
        password = getpass.getpass(f"CloudGuard password for {username}: ")
        opener = authenticated_opener(username, password)
        images = [item.strip() for item in args.images.split(",") if item.strip()]
        if not images:
            raise RuntimeError("No image tags were provided.")
        cache_volume = "cloudguard_trivy_cache"
        run_command(["docker", "volume", "create", cache_volume], timeout=30)
        failures = 0
        for image in images:
            print(f"[SCAN] {image}")
            try:
                report, raw_report = scan_one(image, args.trivy_image, cache_volume)
                report_file = save_raw_report(image, str(report["image_id"]), str(report["scanner_version"]), report["scanner_metadata"], raw_report)
                upload_report(opener, report)
                summary = report["summary"]
                print("  Image ID: {0}".format(report["image_id"]))
                print("  Saved: {vulnerabilities} vulnerabilities, {misconfigurations} misconfigurations, {secrets} secrets; CRITICAL={critical}, HIGH={high}".format(**summary))
                print(f"  Redacted raw report: {report_file.relative_to(ROOT)}")
            except Exception as error:
                failures += 1
                print(f"  FAILED: {error}", file=sys.stderr)
        print("\nOpen Security Lab and refresh the scan results.")
        if failures:
            print(f"Completed with {failures} image scan failure(s).", file=sys.stderr)
            return 1
        print("All requested image scans completed and were saved.")
        return 0
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
