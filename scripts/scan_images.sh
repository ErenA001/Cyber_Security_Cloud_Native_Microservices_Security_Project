#!/usr/bin/env sh
set -eu

if ! command -v trivy >/dev/null 2>&1; then
  echo "Trivy is required. Install it from https://trivy.dev/ and run this script again." >&2
  exit 1
fi

docker compose build
mkdir -p reports/scan_after
for image in cloudguard-ai/gateway:local cloudguard-ai/auth:local cloudguard-ai/ai:local cloudguard-ai/monitor:local; do
  safe_name=$(printf '%s' "$image" | tr '/:' '__')
  echo "Scanning $image"
  trivy image --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --format json --output "reports/scan_after/${safe_name}.json" "$image"
done

echo "Reports saved in reports/scan_after/"
