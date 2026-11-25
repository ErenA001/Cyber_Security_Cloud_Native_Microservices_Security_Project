# Docker host-port publishing note

Docker Engine can accept a `ports` declaration for a container that is attached only to bridge networks configured with `internal: true`, while silently leaving `NetworkSettings.Ports` empty. Internal networks have no default gateway. In this release, a dedicated Nginx edge proxy joins the internal `frontend` network and the standard `host_ingress` bridge; only the edge proxy publishes `127.0.0.1:8080`. The application gateway remains internal and continues to route to the backend services.

Verify after startup:

```bash
docker compose ps
docker compose port edge 8080
docker inspect cloudguard-ai-edge-1 --format '{{json .NetworkSettings.Ports}}'
curl -i http://127.0.0.1:8080/api/health
```

Expected host mapping: `127.0.0.1:8080`. The `edge` service has a fixed upstream to `gateway:8080`; do not add user-controlled upstreams or expose its port on `0.0.0.0` for this local classroom deployment.
