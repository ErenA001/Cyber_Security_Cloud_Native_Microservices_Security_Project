from __future__ import annotations

import os
from typing import Any

import httpx

MONITOR_INTERNAL_URL = os.getenv("MONITOR_INTERNAL_URL", "http://monitor:8000/internal/events")
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")


async def emit_event(
    event_type: str,
    source: str,
    severity: str = "INFO",
    actor: str | None = None,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> None:
    """Best-effort event delivery. Never send credentials, prompts, or response bodies."""
    if not SERVICE_TOKEN:
        return
    payload = {
        "event_type": event_type,
        "source": source,
        "severity": severity,
        "actor": actor,
        "details": details or {},
        "request_id": request_id,
    }
    try:
        async with httpx.AsyncClient(timeout=2.5) as client:
            await client.post(
                MONITOR_INTERNAL_URL,
                json=payload,
                headers={"X-Service-Token": SERVICE_TOKEN},
            )
    except httpx.HTTPError:
        # Monitoring must not make authentication or AI requests unavailable.
        return
