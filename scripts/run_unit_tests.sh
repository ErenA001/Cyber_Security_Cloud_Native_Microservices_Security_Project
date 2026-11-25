#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
IMAGE=cloudguard-ai/unit-tests:local

echo "Building isolated test runner image..."
docker build --file Dockerfile.test --tag "$IMAGE" .

echo "Running unit tests without network access or project secrets..."
docker run --rm --network none --workdir /workspace \
  --mount "type=bind,source=$ROOT/services,target=/workspace/services,readonly" \
  --mount "type=bind,source=$ROOT/shared,target=/workspace/shared,readonly" \
  --mount "type=bind,source=$ROOT/tests,target=/workspace/tests,readonly" \
  --mount "type=bind,source=$ROOT/scripts,target=/workspace/scripts,readonly" \
  "$IMAGE"
