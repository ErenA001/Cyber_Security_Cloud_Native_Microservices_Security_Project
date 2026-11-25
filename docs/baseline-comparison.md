# Original Repository Baseline vs CloudGuard AI 2.0.1

This comparison is based on the original `Cyber_Security_Cloud_Native_Microservices_Security_Project-main.zip` supplied for CS24. The original README describes an insecure v1, followed by scanning, security fixes, and a secure v2. The table below maps concrete baseline code/configuration to the corresponding 2.0 control.

| Security area | Original repository baseline | CloudGuard AI 2.0.1 | Evidence to collect |
|---|---|---|---|
| Host exposure | Auth, AI, and logger published host ports 5001, 5002, and 5003; gateway published on all interfaces at 8080 | Only the Nginx edge proxy is published, bound to `127.0.0.1:8080`; the application gateway and backend network remain internal | `docker compose ps`; Compose configuration |
| Credentials | Hard-coded plaintext demo users and passwords | Random first-run admin password; Argon2 password hash; self-service password change | Authenticated regression test; source review |
| Session integrity | Base64-encoded username returned as a token | Signed JWT with expiry, issuer, audience, and role; HttpOnly/SameSite cookie | Protected-route tests; cookie flags |
| AI route | `/chat` had no token check or rate limit | Authenticated route and Nginx AI request throttling | Anonymous AI route returns 401; gateway configuration |
| AI prompt | System prompt contained a demo admin code | System prompt contains no demo credential and treats supplied content as untrusted | AI service source review |
| Logging | Raw prompts and model replies were sent to an in-memory logger | Event store records bounded metadata; chat history is a separate per-user SQLite feature | Monitor allowlist; Event Log; chat-history endpoint |
| Log access | `/logs` exposed the in-memory log list publicly | Admin-protected event routes; internal routes hidden at gateway and protected by service token | Anonymous route test; internal service-token test |
| Service-to-service trust | No internal service authentication | Shared internal service token checked with constant-time comparison | Monitor internal endpoint unit test |
| Runtime hardening | Flask debug enabled; no non-root user or read-only filesystem settings | FastAPI/Uvicorn without debug; non-root containers, read-only root filesystems, dropped capabilities, no-new-privileges | Dockerfiles and Compose configuration |
| Container assessment | Trivy was listed as a plan, not an implemented workflow | Local image archive scan with Trivy; scan reports saved in the dashboard | Trivy scan reports for the images and timestamp actually scanned |
| Verification | Test plan described, but no runnable regression suite was present in the supplied ZIP | Unit tests, authenticated security regression script, and lightweight resilience test | Saved assessment reports and terminal output |

## Important interpretation

The original v1 source is retained under `baseline/` as a documented, intentionally insecure reference, not deployed as a live vulnerable service. `scripts/build_baseline_images.py` builds the original images without starting them; `scripts/scan_local_images.py --images ...` can then scan those images with the same Trivy version and settings as the hardened images. The comparison is based on inspection of its supplied source/configuration and tests of the hardened 2.0 implementation. Do not claim that an actual attack was run against the original baseline unless the group separately performs and documents that controlled experiment.

For a quantitative comparison, use the same scanner version and scan settings on both image sets if baseline images are built in an isolated environment. Save the raw Trivy JSON, image digest, scanner version, scan date, and vulnerability database timestamp. The 2.0 project does not invent baseline CVE counts.
