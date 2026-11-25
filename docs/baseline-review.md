# Baseline Review - Original CS24 Prototype

The original uploaded ZIP contains a small Flask application with `auth`, `ai`, and `logger` services behind Nginx. This review is based on those source files and the original Docker Compose configuration.

| Area | Original baseline behaviour | Risk | CloudGuard AI 2.0 change |
|---|---|---|---|
| Authentication | Base64-encoded username returned as token | Token is predictable and unsigned | Signed JWT with expiry, issuer, audience, and required claims |
| Password storage | Hard-coded plaintext demo passwords | Credential disclosure and weak defaults | Random bootstrap account password and Argon2 hash |
| AI endpoint | `/chat` did not validate a token | Unauthenticated use and potential API-cost abuse | Protected endpoint; backend validates the session |
| Logging | Anyone could write and read all logs | Confidentiality and integrity exposure | Internal service token for ingestion; admin-only reads |
| Log content | Raw user message and model response were logged | Sensitive prompt and response retention | Structured event metadata only; chat history is separately stored per user |
| Network exposure | Auth, AI, and logger ports were published | Services bypass the gateway | Only the loopback-bound Nginx edge proxy is published; the application gateway remains internal |
| Gateway | No throttling or security headers | Brute-force and request-abuse exposure | Separate Nginx limits and browser security headers |
| Runtime | Flask debug mode enabled | Debug information and unsafe runtime configuration | FastAPI/Uvicorn without debug mode |
| Containers | No explicit non-root or read-only hardening | Larger impact if a service is compromised | Non-root users, read-only root filesystem, dropped capabilities |
| Image assessment | Trivy appeared as a proposed tool, not a runnable scan workflow | No repeatable container-image evidence | Trivy archive scanning and saved, redacted scan reports |

## Evidence collection

1. The original source is copied to `baseline/` for static review. It is intentionally insecure.
2. Build the original images with `python3 scripts/build_baseline_images.py`. This builds images only; it does not start containers.
3. Scan the baseline image tags with `scripts/scan_local_images.py --images ...`.
4. Scan the hardened CloudGuard images with `python3 scripts/scan_local_images.py` using the same Trivy version and settings.
5. Keep the image IDs, scan timestamps, scanner version, Trivy database metadata when available, and redacted raw JSON files under `reports/trivy/`.
6. Run the authenticated regression and lightweight resilience scripts against the hardened application.

**Never run the original baseline services or expose them to a network.** The original source contains deliberately weak demo credentials, an unsigned token, unauthenticated routes, public logs, and debug mode. The original Compose file is intentionally not included in the 2.0 package.

A synthetic lab event is a demonstration record, not a detected live attack. A Trivy finding is evidence about the specific image archive and scan time, not proof of runtime exploitability.
