# CS24 Classroom Demonstration (7-9 minutes)

## 1. Problem and architecture (60 seconds)

Introduce CloudGuard AI as a local security workspace for cloud-native microservices. Show the Nginx edge proxy, the internal Nginx application gateway, and the Auth, AI, and Monitor services. Explain that only the edge proxy is published on host loopback, the application gateway and backend network remain internal, and the AI service has a separate egress network for NVIDIA NIM. The edge proxy has a fixed upstream to the internal gateway; it is not an open proxy.

## 2. Authentication and access control (60 seconds)

Sign in. Explain Argon2 password hashing, signed JWT validation, HttpOnly/SameSite cookies, and protected monitor routes. If time permits, show the security regression result that verifies anonymous access is rejected.

## 3. Observability (60 seconds)

Open Overview and distinguish the last-24-hour metrics from the all-time event history. Open Event Log and show the event source, severity, actor, and timestamp.

## 4. Safe lab event (60 seconds)

Open Security Lab and generate a brute-force or unauthorized API synthetic event. Emphasize that the lab writes a labelled synthetic record and does not attack a real target.

## 5. Before/after container assessment (90-120 seconds)

Before the presentation, build the original baseline images with `python3 scripts/build_baseline_images.py` (this does not start them), then scan them with the documented `--images cloudguard-baseline/...` command. Scan the hardened images with `python3 scripts/scan_local_images.py`. Explain that both sets use the same pinned Trivy scanner and that the scanner reads exported image archives in an isolated container without a Docker socket. Return to the Security Lab page and compare the same service roles. Discuss actual findings and image IDs if available; do not invent findings if a scan is clean.

## 6. NVIDIA AI triage (90 seconds)

Open AI Analyst and select Analyze latest events. Explain that the AI receives recent structured events and saved scan summaries, then produces a prioritized narrative. Separate observed scan facts from AI hypotheses and recommendations.

## 7. Persistent history and report export (60 seconds)

Show that chat history remains after a page refresh. Open Security Lab and download the JSON security report. Mention that the report includes evidence and known limitations, not a compliance certification.

## 8. Security regression, resilience, and conclusion (60-90 seconds)

Run `python3 tests/security_regression.py` if time allows. If time remains, run `python3 tests/resilience_test.py` to show health checks, restart policies, and a small concurrent health sample. Explain that the project combines gateway hardening, authentication, service isolation, container assessment, monitoring, and AI-assisted triage. State the limitations: local educational deployment, hosted inference, no Kubernetes/service mesh, no automatic remediation, and no guarantee of complete security.

## Presentation fallback

If NVIDIA or the Trivy database is unavailable, show the existing event history and previously saved scan report. Explain the dependency failure honestly. Do not claim that a live inference or scan succeeded unless a successful result is visible.
