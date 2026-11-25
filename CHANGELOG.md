# Changelog

## 2.0.1

- Runtime validation: route Nginx temporary files to the writable `/tmp` tmpfs while retaining the read-only root filesystem.
- Preserve the browser host and port with `proxy_set_header Host $http_host` so same-origin checks receive the expected origin host.
- Align both frontend footer version labels with the `2.0.1` release marker.

- Fixed Docker Engine 29.x host-port publishing on internal-only networks by adding a dedicated loopback-published Nginx edge proxy.
- Kept the application gateway and all application microservices on internal Docker networks; the edge proxy has a fixed upstream to the gateway.
- Added explicit edge-proxy health check, Compose network priority, doctor validation, resilience assertions, and Trivy coverage for the edge image.
- Updated architecture, security-control, baseline-comparison, and classroom demo documentation to describe the two-layer Nginx boundary.


## 2.0.0

- Added persistent, user-scoped AI chat history in SQLite.
- Added a self-service password change flow.
- Added Trivy local image scanning via exported image archives; the scanner container is not given the Docker socket.
- Added persistent scan and security regression assessment reports.
- Added authenticated security regression script, lightweight resilience check, local environment doctor, and isolated Docker unit-test runner.
- Added a source-grounded baseline-vs-hardened comparison mapped to the original CS24 repository.
- Added AI analysis context for recent Trivy reports.
- Added JSON security report export.
- Added consistent SQLite backup script and pinned Compose project name to preserve volumes across folder-based upgrades.
- Clarified last-24-hour metrics versus all-time Event Log records.
- Added stronger Nginx connection limits, JSON rate-limit responses, unknown API 404 responses, and request IDs.
- Added AI database volume, gateway health check, and bounded container logs/processes.
- Expanded course architecture, security controls, privacy, limitations, and demo documentation.
