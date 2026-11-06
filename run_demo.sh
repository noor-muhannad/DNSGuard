#!/usr/bin/env bash
# Quick start: runs DNSGuard on a built-in simulation and opens the dashboard at http://localhost:8080/
cd "$(dirname "$0")"
python3 -m dnsguard_live --bundle dnsguard_bundle_v4.zip --source demo --slow-gap 30 "$@"
