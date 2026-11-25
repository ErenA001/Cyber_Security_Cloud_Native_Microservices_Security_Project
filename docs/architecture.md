# CloudGuard AI - Architecture Notes

## Service responsibilities

| Component | Responsibility | Security boundary |
|---|---|---|
| Nginx edge proxy | Fixed reverse proxy from host loopback to the internal app gateway | Only service published on 127.0.0.1:8080; no user-controlled upstream |
| Nginx application gateway | Static UI, API reverse proxy, request throttling, security headers | Internal only; joins frontend and backend networks |
| Auth service | Login, JWT session issuance, password changes | Argon2 hashes; HttpOnly/SameSite cookie; internal DB volume |
| AI service | NVIDIA NIM requests, event triage, chat history | NVIDIA key is backend-only; user-scoped SQLite history; internal monitor token |
| Monitor service | Events, scan reports, assessment reports, export | Admin-protected public routes; service-token-protected internal routes |

## Network model

The edge proxy joins `frontend` (internal) and `host_ingress` (standard bridge) and publishes only `127.0.0.1:8080`. Its sole upstream is the application gateway; it does not accept arbitrary proxy destinations. The application gateway joins `frontend` and `backend`, both internal. Auth and monitor join only `backend`. AI joins `backend` and `egress`; it needs egress only for hosted NVIDIA inference. No application service port is published to the host. This split is required because Docker does not publish ports for containers attached only to internal networks with no default gateway. It reduces direct exposure but does not replace host firewalling or a production network policy.

## Request flows

### Browser authentication

1. Browser posts credentials through the edge proxy to the internal application gateway.
2. Auth verifies the Argon2 password hash.
3. Auth signs a short-lived JWT and sets it in an HttpOnly, SameSite=Strict cookie.
4. Protected routes validate issuer, audience, expiry, role, and signature.
5. State-changing browser requests must include the non-simple `X-Requested-With` header; cross-site Origin and Fetch Metadata checks are also applied when present.

### AI conversation

1. Browser sends a message through the edge proxy and internal Nginx gateway to the AI route.
2. AI validates the signed-in user and loads only that user's recent conversation history from SQLite.
3. AI sends the system instruction and conversation to NVIDIA over HTTPS.
4. The response and user message are saved locally after successful inference.
5. Event records store model/provider metadata, not raw prompts, responses, or credentials.

### AI event triage

1. AI authenticates to monitor using `X-Service-Token`.
2. Monitor returns recent events and saved scan reports.
3. AI keeps only the fields intended for analysis and labels the evidence as untrusted data.
4. NVIDIA produces a narrative summary, priorities, and defensive recommendations.
5. The analysis is stored in the user's local chat history and an event records that analysis completed.

### Container scan

1. Host script exports a local image using `docker image save`.
2. A pinned Trivy container reads the archive through a read-only bind mount.
3. The scanner has no Docker socket, no host root mount, no added Linux capabilities, and a read-only root filesystem with a temporary writable area and dedicated cache volume.
4. The script summarizes findings and uploads a bounded report through the authenticated gateway.
5. Monitor stores the report and emits a container-scan event.

## Persistence

- `auth_data`: account records and Argon2 password hashes.
- `ai_data`: per-user chat messages.
- `monitor_data`: events, scan reports, and assessment reports.

The database schema is initialized with `CREATE TABLE IF NOT EXISTS`, so a Compose rebuild does not erase existing data.
