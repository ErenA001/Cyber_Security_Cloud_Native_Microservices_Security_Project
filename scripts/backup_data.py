#!/usr/bin/env python3
"""Create consistent SQLite backups from the running Compose services."""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATABASES = [
    ("auth", "/data/auth.db", "auth.db"),
    ("ai", "/data/ai.db", "ai.db"),
    ("monitor", "/data/events.db", "events.db"),
]


def run(command: list[str], timeout: int = 60) -> str:
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError("Docker CLI is not installed or not on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out: {' '.join(command[:4])}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "No output").strip()[-1200:]
        raise RuntimeError(f"Command failed: {' '.join(command[:5])}\n{detail}")
    return result.stdout.strip()


def main() -> int:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = ROOT / "backups" / f"cloudguard-{timestamp}"
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    print(f"Creating consistent SQLite backups in {output.relative_to(ROOT)}")
    try:
        for service, database_path, filename in DATABASES:
            container_id = run(["docker", "compose", "ps", "-q", service], timeout=30)
            if not container_id:
                raise RuntimeError(f"Service {service} is not running. Start the stack before backing up.")
            temp_path = f"/tmp/cloudguard-{filename}"
            code = (
                "import sqlite3; "
                f"src=sqlite3.connect('{database_path}'); "
                f"dst=sqlite3.connect('{temp_path}'); "
                "src.backup(dst); dst.close(); src.close()"
            )
            run(["docker", "compose", "exec", "-T", service, "python", "-c", code], timeout=60)
            destination = output / filename
            run(["docker", "cp", f"{container_id}:{temp_path}", str(destination)], timeout=30)
            os.chmod(destination, 0o600)
            run(["docker", "compose", "exec", "-T", service, "rm", "-f", temp_path], timeout=30)
            print(f"  Saved {filename}")
        print("Backup completed. Keep this directory private; it contains account hashes and local chat/event data.")
        return 0
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        print(f"Partial backup directory retained for inspection: {output}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
