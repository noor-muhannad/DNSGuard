#!/usr/bin/env bash
# Attacker VM (Ubuntu/Debian): authoritative sink for the lab zones + the standard tunnelling tools.
# Run inside the ISOLATED lab network only.  sudo bash setup_attacker.sh
set -euo pipefail
echo "[*] installing tunnelling tools used by the Daumel dataset + python"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# These are the established research tools; install whichever your distro provides.
apt-get install -y -qq python3 git build-essential iodine dns2tcp >/dev/null || true
echo "    (iodine, dns2tcp installed if available in apt)"
echo "    dnscat2:  git clone https://github.com/iagox86/dnscat2 (server is Ruby)"
echo "    dnsexfiltrator: git clone https://github.com/Arno0x/DNSExfiltrator (Windows victim + python server)"

cat <<'EOF'

[OK] attacker VM prepared.

1) Run the measurement sink (answers queries so the tools work, logs what arrives):
     sudo python3 dnslab.py sink --zones io-lab.net cat-lab.net d2t-lab.net exf-lab.net

2) For each real tool run, bracket it with ground-truth marks on the VICTIM:
     python3 dnslab.py mark start --tool iodine --domain io-lab.net --client <victim-ip>
     # run the real iodine client on the victim against this VM, through the lab resolver
     python3 dnslab.py mark stop  --tool iodine

NOTE: the lab resolver (setup_resolver.sh) already forwards *.io-lab.net etc. to this VM,
so the victim only ever talks to the resolver — exactly like a real network.
EOF
