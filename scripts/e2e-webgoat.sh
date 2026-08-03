#!/usr/bin/env bash
# Deprecated: WebGoat E2E was too large / noisy for RadioTracer demos.
# Use java-goof + VulnerableApp instead:
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/e2e-java-apps.sh" "$@"
