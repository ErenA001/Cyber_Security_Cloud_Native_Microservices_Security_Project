# CloudGuard AI — Implementation Progress and Validation Record

**Course:** 1400002063 — Cyber Security
**Group:** CS24
**Assigned topic:** Topic 4 — Security of Cloud-Native Applications and Microservices
**Release reviewed:** CloudGuard AI 2.0.1
**Evidence date:** 26 November 2026
**Environment:** macOS + Docker Desktop, local Docker Compose deployment

## 1. Executive summary

CloudGuard AI 2.0.1 was built and launched successfully on the local Docker Desktop environment. The deployed stack contains five services: Edge Proxy, Application Gateway, Auth, AI, and Monitor. All five containers reached the `healthy` state. The Edge Proxy publishes only `127.0.0.1:8080`; the application gateway and application services remain internal to the Docker networks.

The first runtime attempt exposed two Edge Proxy configuration issues. Nginx attempted to create temporary directories on the read-only container filesystem, and the proxy did not preserve the host port in the forwarded `Host` header. Both were corrected without disabling the read-only filesystem or changing the application services. The health endpoint subsequently returned HTTP 200, and a same-origin login request reached the Auth validation layer (HTTP 422 for the deliberately empty test body, rather than a cross-origin rejection).

The supplied screenshots also show a successful administrator dashboard session and a completed NVIDIA NIM event-analysis request. This is a successful local demonstration of the overview and AI briefing flow; it is not evidence that every application page or every automated test has been completed. The screenshots were captured before the frontend footer label was corrected in the GitHub update bundle, so the captured footer still reads `v2.0.0`; the source files now show `v2.0.1`, but that visual correction still needs a browser rebuild/reload confirmation.

## 2. Work completed

### 2.1 Release preparation and configuration

- Extracted the 2.0.1 release into a clean, versioned project directory.
- Confirmed the release marker reports `2.0.1`.
- Reused the existing `.env` configuration from the earlier local deployment so that local secrets and service configuration were not regenerated.
- Ran `docker compose config --quiet`; Compose configuration validation completed successfully.
- Kept `.env`, local database files, backups, and generated reports out of the repository. Only `.env.example` is intended for source control.

### 2.2 Data protection before upgrade

Before starting 2.0.1, SQLite backups were created from the running 2.0.0 services using SQLite's backup API and streamed to the host. Each exported database passed `PRAGMA integrity_check`:

| Database | Local backup file | Approximate size | Integrity check |
|---|---|---:|---|
| Authentication | `auth.db` | 12 KB | `ok` |
| AI conversations | `ai.db` | 16 KB | `ok` |
| Monitoring events | `events.db` | 36 KB | `ok` |

The backup directory was `backups/manual-recovery-20261126-002046/` in the user's local 2.0.0 working copy. These files are local recovery material and must not be committed to GitHub because they may contain account hashes, conversation history, and security-event records.

### 2.3 Docker deployment

- Built the 2.0.1 images successfully, including the new `cloudguard-ai/edge:local` image.
- Started the 2.0.1 Compose stack while retaining the fixed Compose project name and persistent volume names.
- Confirmed the following five services reached `healthy`:
  - `edge`
  - `gateway`
  - `auth`
  - `ai`
  - `monitor`
- Confirmed the only host-published service is the Edge Proxy on `127.0.0.1:8080`.

### 2.4 Edge Proxy runtime corrections

Two runtime issues were found and fixed in `edge-proxy/nginx.conf`:

1. **Read-only filesystem compatibility:** Nginx initially failed while trying to create `/var/cache/nginx/fastcgi_temp`. All Nginx temporary paths are now directed to `/tmp`, which is provided as a writable tmpfs by Compose. The container's read-only root filesystem remains enabled.
2. **Same-origin Host header:** The proxy originally forwarded `Host` using `$host`, which omits the non-default port. It now uses `$http_host`, preserving `127.0.0.1:8080` for the Auth service's same-origin checks.

After rebuilding only the Edge Proxy, it reached `healthy` and the API health endpoint returned:

```http
HTTP/1.1 200 OK
```

```json
{"status":"ok","service":"gateway"}
```

A controlled `POST /api/auth/login` request with `Origin: http://127.0.0.1:8080`, `X-Requested-With`, and an empty JSON body returned HTTP 422 because `username` and `password` were intentionally omitted. This is the expected request-validation response and demonstrates that the request was not rejected by the cross-origin check. It is not, by itself, a credential-authentication test.

## 3. Demonstrated application behaviour

The supplied dashboard screenshots show the following:

- The administrator dashboard loaded successfully.
- The overview displayed **6 events**, including **1 critical event** and **2 warnings** in the visible summary.
- The recent-event feed showed successful login and AI chat activity, plus explicitly labelled simulated API-denial and brute-force events.
- The service-health panel showed the API Gateway, Auth, AI, and Monitor components as operational/verified.
- After selecting **Analyze recent events**, the AI provider changed from **Configured** to **Connected**, with the interface reporting **Live inference verified**.
- The Analyst Briefing displayed observed patterns and a risk ranking based on the available event records.

The visible briefing explicitly describes the brute-force and unauthorized-access records as simulated. These are safe demonstration records, not evidence of attacks against an external system. The AI briefing is advisory and should be interpreted as a summary of supplied evidence, not as an independently verified incident determination.

## 4. Architecture and security controls in the 2.0.1 release

The documented architecture is:

```text
Browser
  |
  v
Nginx Edge Proxy (127.0.0.1:8080 only)
  |
  v
Internal Nginx Application Gateway
  |                 |                  |
  v                 v                  v
Auth Service       AI Service        Monitor Service
Argon2 + JWT       NVIDIA NIM        SQLite event store
                   SQLite chat      Trivy / assessment reports
```

Implemented controls documented by the release include:

- Argon2 password hashing and signed JWT sessions.
- HttpOnly and SameSite session cookies.
- Origin, Fetch Metadata, and custom request-header checks for state-changing browser requests.
- Internal Docker networks and a loopback-only published edge proxy.
- Backend service-token checks for internal service-to-service requests.
- Non-root application processes, read-only container root filesystems, dropped Linux capabilities, and `no-new-privileges` settings.
- Nginx request limits and security response headers.
- Local SQLite persistence for authentication, AI chat history, monitoring events, and assessment reports.
- A Trivy image-archive scanning workflow that does not mount the Docker socket into the scanner.
- Safe, labelled synthetic security-lab events.

These are implemented design controls, not a claim of production certification or complete security.

## 5. Validation status

| Check | Status | Evidence / note |
|---|---|---|
| Release marker | Passed | `VERSION` reports `2.0.1` |
| Compose configuration | Passed | `docker compose config --quiet` |
| SQLite recovery backups | Passed | Three backups; all `PRAGMA integrity_check` results were `ok` |
| Docker image build | Passed | All five service images built |
| Container health | Passed | All five containers reported `healthy` |
| Edge host-port binding | Passed | `127.0.0.1:8080->8080/tcp` on `edge` |
| API health endpoint | Passed | HTTP 200 and `{"status":"ok","service":"gateway"}` |
| Same-origin request check | Passed at Origin layer | Empty login request returned 422 for missing body fields, not 403 |
| Browser dashboard | Demonstrated | Administrator overview screenshot supplied |
| NVIDIA NIM inference | Demonstrated | UI showed Connected / Live inference verified and AI analysis completed |
| Unit test suite | Not yet evidenced | `sh scripts/run_unit_tests.sh` still needs to be run and its output saved |
| Authenticated security regression | Not yet evidenced | `python3 tests/security_regression.py` still needs to be run |
| Resilience test | Not yet evidenced | `python3 tests/resilience_test.py` still needs to be run |
| Trivy image scans | Not yet evidenced | Scan both baseline and hardened images with the same scanner settings before making quantitative claims |
| Full page-by-page demo | Incomplete | Current screenshots cover Overview and AI event analysis; Security Lab, Event Log, Settings, scan/report export are not shown here |

## 6. Outstanding work before final submission

1. Run and retain the unit-test, security-regression, and resilience-test outputs.
2. Run Trivy against the baseline and hardened image sets with the same scanner version and settings. Record image IDs/digests, scanner version, scan date, vulnerability database timestamp, and actual findings. Do not invent CVE counts or claim a measured improvement before these reports exist.
3. Demonstrate the Security Lab, Event Log, Settings/password-change flow, container scan report, and JSON report export if these are included in the final presentation.
4. Verify that the browser footer displays `v2.0.1` after the UI version-label correction in `frontend/index.html`.
5. Record a full live walkthrough if the group needs a complete feature-by-feature video. The current short MP4 is a screenshot-based overview/AI-triage walkthrough, not a live recording of every feature.
6. Confirm that no `.env`, API key, database, local backup, or private report is staged before pushing to GitHub.

## 7. Repository hygiene and safety notes

- Commit `.env.example`, never the real `.env`.
- Do not commit `backups/`, `*.db`, `*.sqlite3`, API keys, administrator passwords, JWT signing keys, or service tokens.
- Keep the original insecure baseline as a static reference only; do not start the intentionally vulnerable baseline services for a public demonstration.
- Keep all simulations and scans within the group's own local environment and authorized educational scope.
- Do not use `docker compose down -v` during an upgrade; it removes persistent volumes.

## 8. Evidence files

- `docs/screenshots/01-overview-dashboard.jpg` — administrator overview before AI analysis.
- `docs/screenshots/02-ai-analysis-running.jpg` — AI event analysis in progress.
- `docs/screenshots/03-ai-analysis-completed.jpg` — connected NVIDIA provider and completed analyst briefing.
- `docs/demo/cloudguard-ai-overview-demo.mp4` — short silent walkthrough assembled from the supplied screenshots.
- `docs/demo/cloudguard-ai-demo-preview.gif` — animated preview for the README.
