#!/usr/bin/env python3
"""Build, but never run, the intentionally insecure original CS24 baseline images."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "baseline"

IMAGES = [
    ("auth", "services/auth", "cloudguard-baseline/auth:original"),
    ("ai", "services/ai", "cloudguard-baseline/ai:original"),
    ("logger", "services/logger", "cloudguard-baseline/logger:original"),
    ("gateway", "gateway", "cloudguard-baseline/gateway:original"),
]


def run(command: list[str], timeout: int = 900) -> str:
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError("Docker CLI is not installed or not on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out: {' '.join(command[:3])}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "No output").strip()[-1800:]
        raise RuntimeError(f"Command failed: {' '.join(command[:4])}\n{detail}")
    return (result.stdout or result.stderr).strip()


def main() -> int:
    print("Building the original CS24 baseline images for static/container scanning only.")
    print("These images are intentionally insecure. This script does NOT run them.\n")
    try:
        for name, relative_context, tag in IMAGES:
            context = BASELINE / relative_context
            dockerfile = context / "Dockerfile"
            if not dockerfile.is_file():
                raise RuntimeError(f"Missing baseline Dockerfile: {dockerfile}")
            print(f"[BUILD] {name}: {tag}")
            run(["docker", "build", "--pull", "--tag", tag, "--file", str(dockerfile), str(context)])
            digest = run(["docker", "image", "inspect", "--format", "{{.Id}}", tag], timeout=30)
            print(f"  Image ID: {digest}")

        print("\nBaseline images built. They have NOT been started.")
        print("Next scan them with scripts/scan_local_images.py --images cloudguard-baseline/auth:original,cloudguard-baseline/ai:original,cloudguard-baseline/logger:original,cloudguard-baseline/gateway:original")
        return 0
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
