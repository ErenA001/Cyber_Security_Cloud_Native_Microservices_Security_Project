# Cyber Security Project: Securing Microservices – Docker and API Security

> **Course:** 1400002063 – Cyber Security
> **Instructor:** Ahmed El-Hadad
> **Assigned Topic:** 4. Security of Cloud-Native Applications and Microservices
> **Group:** `CS__` (fill in)
> **Deadline:** 23 December 2026

---

## 1. Project Overview

Modern applications are no longer single programs. They are split into small services (microservices), packaged in Docker containers, and talk to each other through APIs. This makes them flexible, but it also creates many new places to attack.

This project builds a small, **live microservice system** that uses an AI model through the NVIDIA NIM API, and then shows **how it can be attacked and how it can be protected**.

**Project in one sentence:** we build a working AI-powered microservice system, attack our own system, fix the weaknesses, and prove the improvement with measurements.

## 2. Objectives

1. Build a live system of 3 small services running in Docker containers.
2. Identify security weaknesses in container, API and service-to-service layers.
3. Apply security controls and compare the system **before and after**.
4. Test the system's stability with failure and load scenarios.
5. Document the results with references to NIST and OWASP guidance.

## 3. Planned Architecture

```
User ──► Gateway (Nginx) ──► Auth Service (JWT)
                         ├─► AI Service ──► NVIDIA NIM API
                         └─► Log / Monitoring Service
```

| Component | Role |
|-----------|------|
| **Gateway** | Single entry point. Checks requests, applies rate limiting. |
| **Auth service** | Login and token (JWT) issuing and validation. |
| **AI service** | Sends user questions to the NVIDIA NIM API. API key is stored as a secret. |
| **Log / Monitoring service** | Collects logs and detects suspicious activity. |

> The final architecture may change as the team decides. This is the starting plan.

## 4. Security Focus Areas

| Area | What we will show |
|------|-------------------|
| **Container security** | Image scanning (Trivy), non-root containers, minimal base images |
| **API security** | Authentication, authorization, rate limiting, input validation (OWASP API Security Top 10, 2023) |
| **Service-to-service security** | Network isolation between services, token checks between services |
| **Secrets management** | API keys never stored in code or in the repository |
| **Monitoring and logging** | Detecting brute-force attempts and abnormal traffic |
| **AI-specific risks** | Prompt injection tests on the AI service |

## 5. Method: "Insecure → Secure"

1. **v1 (insecure):** Build the system with intentional weaknesses.
2. **Scan and attack:** Find the problems with scanners and manual tests on our own system.
3. **v2 (secure):** Apply fixes.
4. **Compare:** Scan and test again, and report the difference.

## 6. Test Plan

- Too many requests in a short time (rate limiting test)
- Wrong password attempts (brute-force detection)
- Access without a token, or with a wrong token
- Oversized or malformed input
- Prompt injection attempts against the AI service
- Random container shutdown (does the system recover automatically?)
- Image vulnerability scan before and after hardening

## 7. Repository Structure (planned)

```
.
├── README.md
├── docker-compose.yml
├── .env.example          # example only, never commit real keys
├── gateway/
├── services/
│   ├── auth/
│   ├── ai/
│   └── logger/
├── tests/
│   ├── attacks/
│   └── resilience/
├── reports/
│   ├── scan_before/
│   └── scan_after/
└── docs/
    └── references.md
```

## 8. Quick Start (to be completed)

```bash
git clone <repo-url>
cd <repo-folder>
cp .env.example .env      # add your own NVIDIA API key
docker compose up --build
```

## 9. Team and Responsibilities

| # | Name | Student ID | Responsibility |
|---|------|------------|----------------|
| 1 | | | Demo application setup (Docker, Compose) |
| 2 | | | Container security and image scanning |
| 3 | | | API security (auth, tokens, OWASP API Top 10) |
| 4 | | | Service-to-service security and secrets |
| 5 | | | Monitoring, logging, report and presentation |

## 10. Timeline

| Dates | Goal |
|-------|------|
| 14–20 Nov | Confirm scope and format, create repo, assign tasks |
| 21 Nov – 4 Dec | Build and scan the insecure version (v1) |
| 5 – 14 Dec | Apply security controls (v2) |
| 15 – 20 Dec | Attack and resilience tests, report, slides |
| 21 – 22 Dec | Rehearsal and backup plan |
| 23 Dec | Deadline |

## 11. Status

- [ ] Scope and format confirmed with the instructor
- [ ] Repository and team access ready
- [ ] v1 (insecure) system running
- [ ] Scan results saved
- [ ] v2 (secure) system running
- [ ] Tests completed
- [ ] Report written
- [ ] Presentation ready

## 12. References

- Souppaya, M., Morello, J., Scarfone, K. (2017). *Application Container Security Guide.* NIST SP 800-190. https://doi.org/10.6028/NIST.SP.800-190
- Chandramouli, R. (2019). *Security Strategies for Microservices-based Application Systems.* NIST SP 800-204. https://doi.org/10.6028/NIST.SP.800-204
- OWASP. *API Security Top 10 – 2023.* https://owasp.org/API-Security/
- Berardi, D., Giallorenzo, S., Mauro, J., Melis, A., Montesi, F., Prandini, M. (2022). *Microservice security: a systematic literature review.* PeerJ Computer Science. https://doi.org/10.7717/peerj-cs.779
- Haindl, P., Kochberger, P., Sveggen, M. (2024). *A Systematic Literature Review of Inter-Service Security Threats and Mitigation Strategies in Microservice Architectures.* IEEE Access.
- Rice, L. (2025). *Container Security,* 2nd Edition. O'Reilly Media.

## 13. Notes and Limits

- This project is for **educational purposes only**. All attacks and tests are run only against our own system.
- The NVIDIA NIM free API is meant for prototyping, research and testing, not for production use. It has rate limits and can change.
- **Never commit API keys or passwords to this repository.** Use `.env` (listed in `.gitignore`) and share only `.env.example`.