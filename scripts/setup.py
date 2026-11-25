#!/usr/bin/env python3
"""Create a local .env with fresh secrets and a one-time admin password."""
from __future__ import annotations

import argparse
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare CloudGuard AI local environment")
    parser.add_argument("--force", action="store_true", help="replace an existing .env file")
    args = parser.parse_args()

    if ENV_FILE.exists() and not args.force:
        print(".env already exists; leaving it unchanged. Use --force only if you intend to rotate all local credentials.")
        return 0

    content = EXAMPLE.read_text(encoding="utf-8")
    admin_password = secrets.token_urlsafe(18)
    replacements = {
        "JWT_SECRET_KEY=GENERATE_WITH_SETUP_SCRIPT": f"JWT_SECRET_KEY={secrets.token_urlsafe(48)}",
        "SERVICE_TOKEN=GENERATE_WITH_SETUP_SCRIPT": f"SERVICE_TOKEN={secrets.token_urlsafe(36)}",
        "BOOTSTRAP_ADMIN_PASSWORD=GENERATE_WITH_SETUP_SCRIPT": f"BOOTSTRAP_ADMIN_PASSWORD={admin_password}",
    }
    for old, new in replacements.items():
        content = content.replace(old, new)

    ENV_FILE.write_text(content, encoding="utf-8")
    try:
        ENV_FILE.chmod(0o600)
    except OSError:
        pass

    print("CloudGuard AI environment created.")
    print("Add your NVIDIA API key to .env (NVIDIA_API_KEY=...).")
    print("First-run administrator credentials:")
    print("  Username: admin")
    print(f"  Password: {admin_password}")
    print("Save this password securely. It is not displayed by the application.")
    print("Next: docker compose up --build")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
