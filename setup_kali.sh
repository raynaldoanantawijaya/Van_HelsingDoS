#!/bin/bash
# ================================================================
#  Van_HelsingDoS — Kali Linux Setup Script
#  Run with: chmod +x setup_kali.sh && sudo ./setup_kali.sh
# ================================================================

set -e

RED='\033[0;91m'
GREEN='\033[0;92m'
CYAN='\033[0;96m'
YELLOW='\033[0;93m'
RESET='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║       Van_HelsingDoS — Kali Linux Setup      ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# ---- 1. System Dependencies ----
echo -e "${YELLOW}[1/6] Installing system dependencies...${RESET}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv libssl-dev libffi-dev \
    build-essential libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libdbus-1-3 libxkbcommon0 libx11-6 libxcomposite1 \
    libxdamage1 libxext6 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 2>/dev/null || true

# ---- 2. Python Dependencies ----
echo -e "${YELLOW}[2/6] Installing Python dependencies...${RESET}"
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || \
pip3 install -r requirements.txt

# ---- 3. Playwright Browser ----
echo -e "${YELLOW}[3/6] Installing Playwright Chromium (for Turnstile bypass)...${RESET}"
python3 -m playwright install chromium
python3 -m playwright install-deps chromium 2>/dev/null || true

# ---- 4. File Descriptor Limits ----
echo -e "${YELLOW}[4/6] Configuring file descriptor limits...${RESET}"
if ! grep -q "Van_HelsingDoS" /etc/security/limits.conf 2>/dev/null; then
    echo "" >> /etc/security/limits.conf
    echo "# Van_HelsingDoS - High FD Limits" >> /etc/security/limits.conf
    echo "* soft nofile 1000000" >> /etc/security/limits.conf
    echo "* hard nofile 1000000" >> /etc/security/limits.conf
    echo "root soft nofile 1000000" >> /etc/security/limits.conf
    echo "root hard nofile 1000000" >> /etc/security/limits.conf
    echo -e "${GREEN}  → FD limits configured (requires re-login to take effect)${RESET}"
else
    echo -e "${GREEN}  → FD limits already configured${RESET}"
fi

# Also set for current session
ulimit -n 1000000 2>/dev/null || ulimit -n 500000 2>/dev/null || ulimit -n 100000 2>/dev/null || true

# ---- 5. Sysctl Tuning ----
echo -e "${YELLOW}[5/6] Applying kernel network optimizations...${RESET}"
SYSCTL_CONF="/etc/sysctl.d/99-vanhelsingdos.conf"
cat > "$SYSCTL_CONF" << 'EOF'
# Van_HelsingDoS — Network Performance Tuning
# Maximum number of open files / sockets
fs.file-max = 2097152
fs.nr_open = 2097152

# TCP/UDP Performance
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3

# Connection tracking (for NAT/proxy)
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576

# UDP Buffer
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOF

sysctl -p "$SYSCTL_CONF" 2>/dev/null || true
echo -e "${GREEN}  → Kernel parameters applied${RESET}"

# ---- 6. Verification ----
echo -e "${YELLOW}[6/6] Verifying installation...${RESET}"
echo ""

# Check Python
PYVER=$(python3 --version 2>&1)
echo -e "  Python:       ${GREEN}${PYVER}${RESET}"

# Check uvloop
python3 -c "import uvloop; print('  uvloop:       \033[92mInstalled (' + uvloop.__version__ + ')\033[0m')" 2>/dev/null || \
echo -e "  uvloop:       ${RED}NOT INSTALLED${RESET}"

# Check httpx
python3 -c "import httpx; print('  httpx:        \033[92mInstalled (' + httpx.__version__ + ')\033[0m')" 2>/dev/null || \
echo -e "  httpx:        ${RED}NOT INSTALLED${RESET}"

# Check impacket
python3 -c "import impacket; print('  impacket:     \033[92mInstalled\033[0m')" 2>/dev/null || \
echo -e "  impacket:     ${YELLOW}NOT INSTALLED (raw socket methods unavailable)${RESET}"

# Check tls_client
python3 -c "import tls_client; print('  tls-client:   \033[92mInstalled (JA3 Stealth ACTIVE)\033[0m')" 2>/dev/null || \
echo -e "  tls-client:   ${YELLOW}NOT INSTALLED (JA3 fingerprint evasion disabled)${RESET}"

# Check Playwright
python3 -c "from playwright.sync_api import sync_playwright; print('  Playwright:   \033[92mInstalled\033[0m')" 2>/dev/null || \
echo -e "  Playwright:   ${RED}NOT INSTALLED${RESET}"

# Check FD limit
FDLIMIT=$(ulimit -n)
echo -e "  FD Limit:     ${GREEN}${FDLIMIT}${RESET}"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║           Setup Complete!                     ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${GREEN}Usage:${RESET}"
echo -e "  L7: ${CYAN}python3 start.py GET https://target.com 0 1000 0 100 60${RESET}"
echo -e "  L4: ${CYAN}sudo python3 start.py SYN 1.2.3.4:80 500 60${RESET}"
echo ""
echo -e "${YELLOW}NOTE: Raw socket methods (SYN, ICMP, AMP) require sudo/root!${RESET}"
echo -e "${YELLOW}NOTE: Re-login or 'ulimit -n 1000000' for FD limits to take effect.${RESET}"
