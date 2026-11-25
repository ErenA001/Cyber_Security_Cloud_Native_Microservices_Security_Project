# CloudGuard AI - Security Controls and Evidence

This document separates configured controls from what the project can actually prove during a classroom demonstration.

| Area | Implemented control | Demonstration evidence | Limitation |
|---|---|---|---|
| Authentication | Argon2 password hashing and signed JWT session | Login, protected endpoints, password change | No MFA or enterprise identity provider |
| Session | HttpOnly and SameSite=Strict cookie | Browser cookie flags and API session check | Local HTTP means Secure cookie is disabled by default |
| CSRF | Custom request header, Origin and Fetch Metadata checks | Regression test sends a state-changing request without the header | Not a replacement for a full production threat model |
| Gateway | Nginx request limits and security headers | HTTP response headers and safe rate-limit scenario | Edge proxy has a standard bridge for port publishing; keep its fixed upstream and apply host firewalling outside local demos |
| Service isolation | Internal backend/frontend networks; only loopback edge proxy published | `docker compose ps`, `docker compose port edge 8080`, and Compose network configuration | No Kubernetes NetworkPolicy or service mesh |
| Service authentication | Shared internal service token with constant-time comparison | Gateway hides internal monitor routes; monitor rejects requests without token | Token rotation is manual via environment regeneration |
| Container hardening | Non-root processes, read-only root filesystems, dropped capabilities | Compose configuration and container inspection | Base-image and dependency patching remain operator tasks |
| Image assessment | Trivy image archive scanning | Saved scan report in Security Lab | Does not prove runtime exploitability or scan running processes |
| Event monitoring | SQLite event store and severity summaries | Event Log and dashboard metrics | Local event store is not a SIEM |
| AI analysis | NVIDIA NIM, structured evidence context, prompt-injection signal heuristic | AI Analyst reviews recent events and scan findings | AI output is advisory; heuristics cannot guarantee prompt-injection prevention |
| Data protection | API keys stay backend-side; event allowlist omits raw prompts and credentials | Source review and API health response | Prompts are sent to NVIDIA when inference is requested |

## Safe classroom scenarios

The Security Lab can generate synthetic events for brute-force patterns, unauthorized API access, container vulnerability signals, prompt-injection patterns, and rate-limit events. These records are intentionally marked as simulated. They are useful for explaining detection and triage workflows, but they do not demonstrate a real attack or prove a control blocked an attack.

## Evidence hierarchy

1. Automated tests prove the tested code path behaved as expected in the test environment.
2. The authenticated regression script tests selected controls against the running local stack.
3. Trivy reports identify packages and configuration findings in the specific image archive scanned at a specific time.
4. AI analysis summarizes supplied evidence and may be wrong; it does not independently verify facts.

A clean test or scan is not a guarantee that the system is secure.
