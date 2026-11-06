#!/usr/bin/env bash
# Resolver VM (Ubuntu/Debian): dnsmasq as the lab's DNS server + query log that DNSGuard reads.
# Run inside the ISOLATED lab network only.  sudo bash setup_resolver.sh [ATTACKER_IP]
set -euo pipefail
ATTACKER_IP="${1:-10.10.0.3}"

echo "[*] installing dnsmasq + python"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq dnsmasq python3 tcpdump >/dev/null
systemctl stop systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true

echo "[*] writing /etc/dnsmasq.d/lab.conf"
cat >/etc/dnsmasq.d/lab.conf <<EOF
# --- DNSGuard lab resolver ---
log-queries                 # every query is logged -> DNSGuard reads this file
log-facility=/var/log/dnsmasq/queries.log
no-resolv
server=1.1.1.1              # upstream for normal names (lab has no real internet? then point benign traffic elsewhere)
cache-size=1000
# send the lab attack zones to the attacker VM's authoritative sink:
server=/io-lab.net/${ATTACKER_IP}
server=/cat-lab.net/${ATTACKER_IP}
server=/d2t-lab.net/${ATTACKER_IP}
server=/exf-lab.net/${ATTACKER_IP}
# DNSGuard writes blocks here:
conf-file=/etc/dnsmasq.d/dnsguard-block.conf
EOF

mkdir -p /var/log/dnsmasq
: >/etc/dnsmasq.d/dnsguard-block.conf
touch /var/log/dnsmasq/queries.log
systemctl enable dnsmasq >/dev/null 2>&1 || true
systemctl restart dnsmasq
echo "[*] allow dnsmasq to reload its block file without a password (for DNSGuard block mode):"
echo '    add to /etc/sudoers.d/dnsguard:  <user> ALL=(root) NOPASSWD: /bin/systemctl reload dnsmasq, /usr/bin/pkill -HUP dnsmasq'

cat <<EOF

[OK] resolver ready.
   query log : /var/log/dnsmasq/queries.log
   block file: /etc/dnsmasq.d/dnsguard-block.conf

Point the VICTIM VMs' DNS at THIS machine's IP, then force all DNS through it:
   sudo iptables -I FORWARD -p udp ! -d $(hostname -I | awk '{print $1}') --dport 53 -j DROP
   sudo iptables -I FORWARD -p tcp ! -d $(hostname -I | awk '{print $1}') --dport 53 -j DROP

Run DNSGuard on this machine:
   python3 -m dnsguard_live --bundle dnsguard_bundle_v4.zip \\
       --source dnsmasq:/var/log/dnsmasq/queries.log \\
       --mode block --block-backend dnsmasq \\
       --reload-cmd "sudo systemctl reload dnsmasq" \\
       --never-block uobabylon.edu.iq
EOF
