#!/bin/bash

set -e

WORK_DIR="/opt/whispera"
BIN_PATH="/usr/local/bin"
DAT_PATH="/usr/local/share/whispera"
CONF_PATH="/etc/whispera"
BRANCH="main"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
log_info() { echo -e "${BLUE}[INFO]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERR]${PLAIN} $1"; }

INTEGRITY_ENV_FILE="$CONF_PATH/whispera.env"

load_integrity_key() {
    [[ -n "$WHISPERA_INTEGRITY_KEY" ]] && return 0
    [[ -f "$INTEGRITY_ENV_FILE" ]] || return 0
    local existing
    existing=$(sed -n 's/^WHISPERA_INTEGRITY_KEY=//p' "$INTEGRITY_ENV_FILE" 2>/dev/null | head -n1)
    if [[ -n "$existing" ]]; then
        export WHISPERA_INTEGRITY_KEY="$existing"
    fi
    return 0
}

refresh_config() {
    local cfg="${1:-$CONF_PATH/config.yaml}"
    if [[ ! -f "$cfg" ]]; then return 0; fi
    load_integrity_key
    local bin
    bin=$(command -v whispera 2>/dev/null) || bin="$BIN_PATH/whispera"
    if [[ ! -x "$bin" ]]; then
        log_warn "whispera binary not found ($bin) — checksum NOT updated; integrity check may fail on restart"
        return 0
    fi
    if "$bin" update-checksum "$cfg" >/dev/null 2>&1; then
        log_info "Config checksum updated"
    else
        log_warn "update-checksum failed for $cfg — integrity check may fail on restart"
    fi
    return 0
}

_enable_chameleon_in_config() {
    local cfg="${CONF_PATH}/config.yaml"
    [[ -f "$cfg" ]] || return

    local cert="${CONF_PATH}/chameleon.crt" key="${CONF_PATH}/chameleon.key"
    if [[ ! -f "$cert" || ! -f "$key" ]] && command -v openssl &>/dev/null; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$key" -out "$cert" \
            -days 3650 -subj "/CN=whispera" 2>/dev/null
        chmod 600 "$key"
    fi

    if grep -q "^chameleon:" "$cfg"; then
        sed -i '/^chameleon:/,/^[^ ]/{s/enabled: false/enabled: true/}' "$cfg"
        local cur_domain
        cur_domain=$(awk '/^chameleon:/{f=1} f && /^[[:space:]]+domain:/{print $2; exit}' "$cfg" | tr -d '"')
        if [[ -n "$cur_domain" ]]; then
            refresh_config "$cfg"
            log_success "Chameleon enabled in config.yaml (autocert domain=$cur_domain, tls_cert untouched)"
            return
        fi
        local cur_cert
        cur_cert=$(awk '/^chameleon:/{f=1} f && /tls_cert:/{print $2; exit}' "$cfg" | tr -d '"')
        if [[ -z "$cur_cert" && -n "$cert" ]]; then
            python3 - "$cfg" "$cert" "$key" <<'PYEOF'
import sys, re
path, cert, key = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    text = f.read()
def patch_block(m):
    blk = m.group(0)
    blk = re.sub(r'tls_cert:\s*""', f'tls_cert: "{cert}"', blk)
    blk = re.sub(r'tls_key:\s*""',  f'tls_key: "{key}"',   blk)
    return blk
text = re.sub(r'^chameleon:.*?(?=\n\S|\Z)', patch_block, text, flags=re.S|re.M)
with open(path, 'w') as f:
    f.write(text)
PYEOF
            log_info "Chameleon: injected self-signed TLS cert into existing config"
        fi
    else
        printf '\nchameleon:\n  enabled: true\n  listen_addr: ":443"\n  tls_cert: "%s"\n  tls_key: "%s"\n  domain: ""\n  acme_dir: "/var/lib/whispera/acme"\n' \
            "${cert}" "${key}" >> "$cfg"
    fi
    if command -v ufw &>/dev/null; then
        ufw allow 443/tcp >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    refresh_config "$cfg"
    log_success "Chameleon enabled in config.yaml"
}


_enable_ml_in_config() {
    local cfg="${CONF_PATH}/config.yaml"
    [[ -f "$cfg" ]] || return
    if grep -q "^ml:" "$cfg"; then
        sed -i '/^ml:/,/^[^ ]/{s/enabled: false/enabled: true/}' "$cfg"
    else
        printf '\nml:\n  enabled: true\n  server_url: "https://127.0.0.1:8000"\n  token_file: ""\n' >> "$cfg"
    fi
    refresh_config "$cfg"
    log_success "ML enabled in config.yaml"
}

get_public_ip() {
    local IP
    IP=$(curl -s https://2ip.ru/api/self -m 5 2>/dev/null | grep -oE '"ip":"[^"]*"' | cut -d'"' -f4)
    if [[ -z "$IP" ]]; then
        IP=$(curl -s https://2ip.io -m 5 2>/dev/null | tr -d '[:space:]')
    fi
    if [[ -z "$IP" ]]; then
        IP=$(curl -s https://api.ipify.org -m 5 2>/dev/null)
    fi
    if [[ -z "$IP" ]]; then
        IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
    fi
    echo "${IP:-localhost}"
}

gen_password() {
    local len=${1:-30}
    if command -v openssl &>/dev/null; then
        openssl rand -base64 40 | tr -dc 'A-Za-z0-9' | head -c "$len"
    else
        head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "$len"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        RELEASE=$ID
    fi
}


restore() {
    log_warn "Update failed or service unstable. Rolling back..."

    if [[ -f "$BIN_PATH/whispera.bak" ]]; then
        log_info "Restoring server binary..."
        cp -f "$BIN_PATH/whispera.bak" "$BIN_PATH/whispera"
        chmod +x "$BIN_PATH/whispera"
    fi

    if [[ -d "$DAT_PATH/panel.bak" ]]; then
        log_info "Restoring panel..."
        rm -rf "$DAT_PATH/panel"
        cp -r "$DAT_PATH/panel.bak" "$DAT_PATH/panel"
    fi

    systemctl daemon-reload
    if systemctl restart whispera 2>/dev/null; then
        log_success "Rollback complete. System restored to previous state."
    else
        log_warn "Rollback restart also failed. Trying start..."
        systemctl start whispera 2>/dev/null || log_warn "Service could not be started. Run: systemctl start whispera"
    fi
    exit 1
}

setup_bbr() {
    log_info "Enabling BBR TCP congestion control..."
    
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_info "BBR already enabled"
        return
    fi
    
    local KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    local KERNEL_MINOR=$(uname -r | cut -d. -f2)
    
    if [[ $KERNEL_MAJOR -lt 4 ]] || [[ $KERNEL_MAJOR -eq 4 && $KERNEL_MINOR -lt 9 ]]; then
        log_warn "Kernel too old for BBR (requires 4.9+)"
        return
    fi
    
    if ! grep -q "tcp_congestion_control" /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null; then
        cat >> /etc/sysctl.conf <<EOF

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    fi

    sysctl -p >/dev/null 2>&1

    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_success "BBR enabled"
    else
        log_warn "BBR enable failed"
    fi
}

setup_warp() {
    log_info "Setting up Cloudflare WARP..."
    
    if ! command -v warp-cli &>/dev/null; then
        case $RELEASE in
            ubuntu|debian)
                curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
                echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflare-client.list
                apt-get update >/dev/null 2>&1
                apt-get install -y cloudflare-warp >/dev/null 2>&1
                ;;
            centos|fedora|almalinux|rocky)
                curl -fsSL https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo > /etc/yum.repos.d/cloudflare-warp.repo
                yum install -y cloudflare-warp >/dev/null 2>&1
                ;;
            *)
                log_warn "WARP not supported on $RELEASE"
                return
                ;;
        esac
        if ! command -v warp-cli &>/dev/null; then
            log_warn "WARP installation failed"
            return
        fi
    fi

    systemctl enable warp-svc --now 2>/dev/null || true
    sleep 2

    if ! warp-cli status 2>/dev/null | grep -q "Connected"; then
        if warp-cli registration new &>/dev/null; then
            warp-cli mode proxy 2>/dev/null || true
        else
            warp-cli --accept-tos register 2>/dev/null || true
            warp-cli set-mode proxy 2>/dev/null || true
        fi
        warp-cli connect 2>/dev/null || true
        for i in $(seq 1 5); do
            sleep 3
            warp-cli status 2>/dev/null | grep -q "Connected" && break
            log_info "Waiting for WARP... ($((i*3))s)"
        done
    fi

    if warp-cli status 2>/dev/null | grep -q "Connected"; then
        log_success "WARP connected (SOCKS5 proxy on 127.0.0.1:40000)"

        if [[ -f "$CONF_PATH/config.yaml" ]]; then
            log_info "Auto-configuring Whispera to use WARP..."

            if grep -q "^relay:" "$CONF_PATH/config.yaml"; then
                if grep -q "upstream_proxy:" "$CONF_PATH/config.yaml"; then
                    sed -i 's|upstream_proxy:.*|upstream_proxy: "socks5://127.0.0.1:40000"|' "$CONF_PATH/config.yaml"
                else
                    sed -i '/^relay:/a \ \ upstream_proxy: "socks5://127.0.0.1:40000"' "$CONF_PATH/config.yaml"
                fi
            else
                printf '\nrelay:\n  upstream_proxy: "socks5://127.0.0.1:40000"\n' >> "$CONF_PATH/config.yaml"
            fi

            log_success "Configuration updated."
            refresh_config
            systemctl restart whispera 2>/dev/null || true
        else
            log_warn "Config file not found at $CONF_PATH/config.yaml - please configure manually"
        fi
    else
        log_warn "WARP connection failed. Run 'warp-cli connect' manually."
    fi
}

setup_fail2ban() {
    log_info "Setting up Fail2ban..."

    if [[ -f /etc/fail2ban/jail.local ]] && systemctl is-active --quiet fail2ban 2>/dev/null; then
        log_success "Fail2ban already installed and configured"
        log_info "Config: /etc/fail2ban/jail.local"
        return
    fi

    case $RELEASE in
        ubuntu|debian) apt-get install -y fail2ban >/dev/null 2>&1 ;;
        centos|fedora|almalinux|rocky) yum install -y fail2ban >/dev/null 2>&1 ;;
        *) log_warn "Fail2ban not supported"; return ;;
    esac

    if ! command -v fail2ban-server &>/dev/null; then
        log_warn "Fail2ban installation failed"
        return
    fi

    mkdir -p /etc/fail2ban

    cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 24h
findtime = 2m
maxretry = 3
backend  = systemd

[sshd]
enabled = true

[whispera]
enabled   = true
backend   = systemd
journalmatch = _SYSTEMD_UNIT=whispera.service
maxretry  = 5
findtime  = 1m
bantime   = 6h
filter    = whispera

EOF

    mkdir -p /etc/fail2ban/filter.d
    cat > /etc/fail2ban/filter.d/whispera.conf <<'EOF'
[Definition]
failregex = .*handshake failed.*<HOST>
            .*auth failed.*<HOST>
            .*invalid key.*<HOST>
            .*connection rejected.*<HOST>
ignoreregex =
EOF

    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1
    sleep 2

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        log_success "Fail2ban installed and running (sshd + whispera jails)"
        log_info "Config: /etc/fail2ban/jail.local"
    else
        log_warn "Fail2ban installed but not running. Check: journalctl -u fail2ban"
    fi
}

setup_redis() {
    log_info "Setting up Redis..."
    
    if command -v redis-server &>/dev/null; then
        if systemctl is-active --quiet redis-server 2>/dev/null || systemctl is-active --quiet redis 2>/dev/null; then
            log_success "Redis already installed and running"
            return
        fi
    fi
    
    case $RELEASE in
        ubuntu|debian)
            apt-get update >/dev/null 2>&1
            apt-get install -y redis-server >/dev/null 2>&1
            ;;
        centos|fedora|almalinux|rocky)
            yum install -y redis >/dev/null 2>&1
            ;;
        *) log_warn "Redis not supported on $RELEASE"; return ;;
    esac
    
    if ! command -v redis-server &>/dev/null; then
        log_warn "Redis installation failed"
        return
    fi
    
    local REDIS_CONF="/etc/redis/redis.conf"
    [[ -f "/etc/redis.conf" ]] && REDIS_CONF="/etc/redis.conf"
    
    if [[ -f "$REDIS_CONF" ]]; then
        sed -i 's/^bind .*/bind 127.0.0.1/' "$REDIS_CONF" 2>/dev/null || true
        grep -q "^maxmemory " "$REDIS_CONF" || echo "maxmemory 256mb" >> "$REDIS_CONF"
        grep -q "^maxmemory-policy " "$REDIS_CONF" || echo "maxmemory-policy allkeys-lru" >> "$REDIS_CONF"
    fi
    
    systemctl enable redis-server 2>/dev/null || systemctl enable redis 2>/dev/null
    systemctl restart redis-server 2>/dev/null || systemctl restart redis 2>/dev/null
    
    if redis-cli ping 2>/dev/null | grep -q "PONG"; then
        log_success "Redis installed on 127.0.0.1:6379"
        echo ""
        log_info "Add to config.yaml: cache.redis_url: \"redis://127.0.0.1:6379\""
    else
        log_warn "Redis installed but not responding"
    fi
}

setup_postgres() {
    log_info "Setting up PostgreSQL..."
    
    if command -v psql &>/dev/null && systemctl is-active --quiet postgresql 2>/dev/null; then
        if sudo -u postgres psql -lqt 2>/dev/null | grep -q whispera; then
            log_success "PostgreSQL already installed with whispera database"
            return
        fi
    fi
    
    case $RELEASE in
        ubuntu|debian)
            apt-get update >/dev/null 2>&1
            apt-get install -y postgresql postgresql-contrib >/dev/null 2>&1
            ;;
        centos|fedora|almalinux|rocky)
            yum install -y postgresql-server postgresql >/dev/null 2>&1
            postgresql-setup --initdb 2>/dev/null || true
            ;;
        *) log_warn "PostgreSQL not supported on $RELEASE"; return ;;
    esac
    
    if ! command -v psql &>/dev/null; then
        log_warn "PostgreSQL installation failed"
        return
    fi
    
    systemctl enable postgresql >/dev/null 2>&1
    systemctl start postgresql >/dev/null 2>&1
    sleep 2
    
    local PG_PASS=$(gen_password 30)
    
    sudo -u postgres psql <<EOF >/dev/null 2>&1
CREATE USER whispera WITH PASSWORD '$PG_PASS';
CREATE DATABASE whispera OWNER whispera;
GRANT ALL PRIVILEGES ON DATABASE whispera TO whispera;
EOF
    
    mkdir -p "$CONF_PATH"
    cat > "$CONF_PATH/postgres.env" <<EOF
POSTGRES_USER=whispera
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=whispera
POSTGRES_URL=postgresql://whispera:$PG_PASS@localhost/whispera
EOF
    chmod 600 "$CONF_PATH/postgres.env"
    
    if sudo -u postgres psql -lqt 2>/dev/null | grep -q whispera; then
        log_success "PostgreSQL installed"
        log_info "Credentials: /etc/whispera/postgres.env"
    else
        log_warn "PostgreSQL database creation failed"
    fi
}

setup_swap() {
    log_info "Setting up Swap..."
    
    if swapon --show | grep -q "/"; then
        log_info "Swap already exists"
        return
    fi
    
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    
    sysctl vm.swappiness=10 >/dev/null 2>&1
    grep -q "vm.swappiness" /etc/sysctl.conf || echo "vm.swappiness=10" >> /etc/sysctl.conf
    log_success "Swap 2GB created"
}

setup_sysctl() {
    log_info "Optimizing system..."

    cat > /etc/sysctl.d/99-whispera.conf <<'EOF'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_fastopen = 3
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
fs.file-max = 1000000
EOF

    sysctl --system >/dev/null 2>&1
    log_success "System optimized"
}

setup_autoupdate() {
    log_info "Setting up auto-update..."
    
    cat > /etc/cron.daily/whispera-update <<'CRONEOF'
WORK_DIR="__WORK_DIR__"
BIN_PATH="__BIN_PATH__"
BRANCH="__BRANCH__"
LOG="/var/log/whispera-update.log"
exec >> "$LOG" 2>&1
echo "=== $(date) ==="

cd "$WORK_DIR" || exit 1
git config --global --add safe.directory "$WORK_DIR" 2>/dev/null || true

BEFORE=$(git rev-parse HEAD)
git pull origin "$BRANCH" --quiet
AFTER=$(git rev-parse HEAD)

if [[ "$BEFORE" == "$AFTER" ]]; then
    echo "No changes."
    exit 0
fi

CHANGED=$(git diff --name-only "$BEFORE" "$AFTER")
echo "Changed files:"
echo "$CHANGED"

GO_CHANGED=$(echo "$CHANGED" | grep -E '\.(go)$|^go\.(mod|sum)$' || true)
ML_PY_CHANGED=$(echo "$CHANGED" | grep -E '^(neural|ml_engine)/.*\.py$' || true)
PANEL_CHANGED=$(echo "$CHANGED" | grep -E '^panel/' || true)

if [[ -n "$ML_PY_CHANGED" ]]; then
    echo "ML files updated — restarting whispera (ML is built-in)"
    systemctl restart whispera 2>/dev/null && echo "whispera restarted" || echo "whispera not running"
fi

if [[ -n "$PANEL_CHANGED" ]]; then
    echo "Panel files updated — redeploying static files"
    if [[ -d "panel/public" ]]; then
        FA_BACKUP=""
        if [[ -d "$DAT_PATH/panel/public/vendor/fa" ]]; then
            FA_BACKUP=$(mktemp -d)
            cp -r "$DAT_PATH/panel/public/vendor/fa" "$FA_BACKUP/fa"
        fi
        rm -rf "$DAT_PATH/panel/public"
        mkdir -p "$DAT_PATH/panel"
        cp -r panel/public "$DAT_PATH/panel/public"
        if [[ -n "$FA_BACKUP" ]]; then
            mkdir -p "$DAT_PATH/panel/public/vendor"
            cp -r "$FA_BACKUP/fa" "$DAT_PATH/panel/public/vendor/fa"
            rm -rf "$FA_BACKUP"
        elif [[ ! -f "$DAT_PATH/panel/public/vendor/fa/all.min.css" ]]; then
            FA_VER="6.5.1"
            FA_DIR="$DAT_PATH/panel/public/vendor/fa"
            FA_BASE="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/${FA_VER}"
            mkdir -p "$FA_DIR/webfonts"
            if curl -fsSL "${FA_BASE}/css/all.min.css" -o "$FA_DIR/all.min.css" 2>/dev/null; then
                for wf in fa-solid-900 fa-regular-400 fa-brands-400; do
                    curl -fsSL "${FA_BASE}/webfonts/${wf}.woff2" -o "$FA_DIR/webfonts/${wf}.woff2" 2>/dev/null || true
                    curl -fsSL "${FA_BASE}/webfonts/${wf}.ttf"   -o "$FA_DIR/webfonts/${wf}.ttf"   2>/dev/null || true
                done
                sed -i "s|../webfonts/|/vendor/fa/webfonts/|g" "$FA_DIR/all.min.css"
            fi
        fi
        chmod -R a+rX "$DAT_PATH/panel/public"
        chown -R whispera:whispera "$DAT_PATH/panel" 2>/dev/null || true
    fi
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null && echo "panel redeployed" || true
fi

if [[ -n "$GO_CHANGED" ]]; then
    echo "Go files updated — rebuilding whispera-server"
    export PATH=$PATH:/usr/local/go/bin
    go build -trimpath -ldflags "-w -s" -o whispera-server ./app/server 2>/dev/null
    if [[ -f whispera-server ]]; then
        cp whispera-server "$BIN_PATH/whispera"
        systemctl restart whispera
        echo "whispera-server rebuilt and restarted"
    else
        echo "Build failed — keeping old binary"
    fi
fi
CRONEOF

    sed -i \
        -e "s|__WORK_DIR__|$WORK_DIR|g" \
        -e "s|__BIN_PATH__|$BIN_PATH|g" \
        -e "s|__BRANCH__|$BRANCH|g" \
        /etc/cron.daily/whispera-update
    chmod +x /etc/cron.daily/whispera-update
    log_success "Auto-update enabled (daily, smart: Go→rebuild, ML-py→restart only)"
}

setup_ssh_hardening() {
    log_info "Hardening SSH..."
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    log_success "SSH hardened (password auth disabled)"
    log_warn "Make sure you have SSH key access!"
}

generate_panel_cert() {
    local CERT="$CONF_PATH/panel.crt"
    local KEY="$CONF_PATH/panel.key"
    local SERVER_IP
    SERVER_IP=$(get_public_ip)

    if [[ -f "$CERT" && -f "$KEY" ]]; then
        if openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -q "whispera-ui"; then
            log_info "Panel TLS cert already exists, skipping generation"
            return
        fi
        log_info "Regenerating panel TLS cert (adding DNS:whispera-ui SAN)..."
        rm -f "$CERT" "$KEY"
    fi

    log_info "Generating self-signed TLS certificate for panel (CN=whispera-ui)..."
    if command -v openssl &>/dev/null; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$KEY" -out "$CERT" \
            -days 3650 -subj "/CN=whispera-ui" \
            -addext "subjectAltName=DNS:whispera-ui,IP:127.0.0.1,IP:${SERVER_IP}" \
            2>/dev/null
        chmod 600 "$KEY"
        log_success "Panel TLS cert generated: $CERT"
    else
        log_warn "openssl not found — panel will run without HTTPS"
    fi
}

setup_decoy_refresh() {
    if ! command -v wget &>/dev/null; then
        if command -v apt-get &>/dev/null; then apt-get install -y wget >/dev/null 2>&1
        elif command -v dnf &>/dev/null; then dnf install -y wget >/dev/null 2>&1
        elif command -v yum &>/dev/null; then yum install -y wget >/dev/null 2>&1
        elif command -v pacman &>/dev/null; then pacman -Sy --noconfirm wget >/dev/null 2>&1
        elif command -v zypper &>/dev/null; then zypper install -y wget >/dev/null 2>&1
        elif command -v apk &>/dev/null; then apk add wget >/dev/null 2>&1
        fi
    fi

    local default_sites="https://ria.ru/,https://lenta.ru/,https://www.rbc.ru/,https://www.kp.ru/,https://tass.ru/,\
https://www.gazeta.ru/,https://www.kommersant.ru/,https://www.vedomosti.ru/,https://www.fontanka.ru/,https://www.ng.ru/,\
https://www.rg.ru/,https://iz.ru/,https://life.ru/,https://www.vesti.ru/,https://www.interfax.ru/,\
https://yandex.ru/,https://mail.ru/,https://www.rambler.ru/,https://ok.ru/,https://go.mail.ru/,\
https://www.ozon.ru/,https://www.wildberries.ru/,https://www.avito.ru/,https://www.citilink.ru/,https://www.dns-shop.ru/,\
https://www.mvideo.ru/,https://www.eldorado.ru/,https://www.lamoda.ru/,https://www.sportmaster.ru/,https://leroymerlin.ru/,\
https://www.sberbank.ru/,https://www.vtb.ru/,https://alfabank.ru/,https://www.gazprombank.ru/,https://www.raiffeisen.ru/,\
https://sovcombank.ru/,https://www.gosuslugi.ru/,https://www.nalog.gov.ru/,https://www.mos.ru/,https://www.gibdd.ru/,\
https://hh.ru/,https://auto.ru/,https://www.cian.ru/,https://www.drom.ru/,https://www.kinopoisk.ru/,\
https://2gis.ru/,https://www.eapteka.ru/,https://www.dixy.ru/,https://www.perekrestok.ru/,https://www.pochta.ru/"
    local sites="${WHISPERA_DECOY_SITES:-$default_sites}"
    local interval="${WHISPERA_DECOY_REFRESH_INTERVAL:-1d}"

    cat > /usr/local/bin/whispera-refresh-decoy.sh <<REFRESHEOF
#!/bin/bash
DECOY_DIR="/var/www/whispera-decoy"
SITES="\${WHISPERA_DECOY_SITES:-$sites}"
IFS=',' read -ra SITE_ARR <<< "\$SITES"
N=\${#SITE_ARR[@]}
[[ \$N -eq 0 ]] && exit 0

command -v wget &>/dev/null || exit 0

MAX_ATTEMPTS=8
[[ \$MAX_ATTEMPTS -gt \$N ]] && MAX_ATTEMPTS=\$N

for ((attempt=0; attempt<MAX_ATTEMPTS; attempt++)); do
    PICK="\${SITE_ARR[\$((RANDOM % N))]}"
    TMP_DIR=\$(mktemp -d)
    wget --quiet --page-requisites --convert-links --adjust-extension \\
        --span-hosts --no-parent --no-host-directories \\
        --timeout=15 --tries=1 -e robots=off \\
        -P "\$TMP_DIR" "\$PICK" 2>/dev/null
    if [[ ! -f "\$TMP_DIR/index.html" ]]; then
        first_html=\$(find "\$TMP_DIR" -maxdepth 1 -name '*.html' | head -n1)
        [[ -n "\$first_html" ]] && cp "\$first_html" "\$TMP_DIR/index.html"
    fi
    if [[ -f "\$TMP_DIR/index.html" ]]; then
        rm -rf "\$DECOY_DIR"
        mkdir -p "\$(dirname "\$DECOY_DIR")"
        mv "\$TMP_DIR" "\$DECOY_DIR"
        logger -t whispera-decoy "refreshed from \$PICK" 2>/dev/null || true
        exit 0
    fi
    rm -rf "\$TMP_DIR"
done

mkdir -p "\$DECOY_DIR"
if [[ ! -f "\$DECOY_DIR/index.html" ]]; then
    cat > "\$DECOY_DIR/index.html" <<'DECOYHTML'
<!doctype html><html><head><title>Welcome</title></head><body><h1>It works.</h1></body></html>
DECOYHTML
fi
REFRESHEOF
    chmod +x /usr/local/bin/whispera-refresh-decoy.sh

    if command -v systemctl &>/dev/null; then
        cat > /etc/systemd/system/whispera-decoy-refresh.service <<'EOF'
[Unit]
Description=Refresh Whispera nginx decoy backend content

[Service]
Type=oneshot
ExecStart=/usr/local/bin/whispera-refresh-decoy.sh
EOF
        cat > /etc/systemd/system/whispera-decoy-refresh.timer <<EOF
[Unit]
Description=Periodically refresh Whispera decoy backend content

[Timer]
OnBootSec=10min
OnUnitActiveSec=${interval}
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable --now whispera-decoy-refresh.timer >/dev/null 2>&1
        log_success "Decoy refresh timer installed (every ${interval}, randomized up to 6h)"
    fi
}

setup_nginx_proxy() {
    local SERVER_IP
    SERVER_IP=$(get_public_ip)

    if ! command -v nginx &>/dev/null; then
        log_info "Installing nginx..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y nginx >/dev/null 2>&1
        elif command -v dnf &>/dev/null; then
            dnf install -y nginx >/dev/null 2>&1
        elif command -v yum &>/dev/null; then
            yum install -y nginx >/dev/null 2>&1
        elif command -v pacman &>/dev/null; then
            pacman -Sy --noconfirm nginx >/dev/null 2>&1
        elif command -v zypper &>/dev/null; then
            zypper install -y nginx >/dev/null 2>&1
        elif command -v apk &>/dev/null; then
            apk add nginx >/dev/null 2>&1
        else
            log_warn "Cannot install nginx — package manager not found"
            return
        fi
    fi
    if ! command -v nginx &>/dev/null; then
        log_warn "nginx install failed (no outbound? unsupported distro) — chameleon decoy backend unavailable until nginx is installed"
        return
    fi

    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/whispera-ratelimit.conf <<'RLCONF'
limit_req_zone $binary_remote_addr zone=panel_auth:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=panel_api:10m  rate=60r/s;
limit_req_status 429;
RLCONF

    setup_decoy_refresh
    if [[ ! -f /var/www/whispera-decoy/index.html ]]; then
        /usr/local/bin/whispera-refresh-decoy.sh >/dev/null 2>&1 || true
    fi

    cat > /etc/nginx/conf.d/whispera-ui.conf <<NGINX
server {
    listen 127.0.0.1:80;
    server_name whispera-ui ${SERVER_IP};
    root /var/www/whispera-decoy;

    location /sub/ {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;
    }

    location = /api/login {
        limit_req  zone=panel_auth burst=5 nodelay;
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;
    }

    location /api/auth/ {
        limit_req  zone=panel_auth burst=5 nodelay;
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;
    }

    location /api/v2/auth/ {
        limit_req  zone=panel_auth burst=5 nodelay;
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;
    }

    location /api/ {
        limit_req  zone=panel_api burst=200 nodelay;
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
NGINX

    if [[ -f /etc/nginx/nginx.conf ]] && ! grep -qE 'include[[:space:]]+.*conf\.d/\*\.conf' /etc/nginx/nginx.conf; then
        sed -i '0,/^[[:space:]]*http[[:space:]]*{/s//&\n    include \/etc\/nginx\/conf.d\/*.conf;/' /etc/nginx/nginx.conf
        log_info "Added conf.d include to nginx.conf (Arch/minimal layouts)"
    fi

    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    rm -f /etc/nginx/sites-available/whispera-ui /etc/nginx/sites-enabled/whispera-ui 2>/dev/null || true

    if command -v ufw &>/dev/null; then
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi

    if nginx -t 2>/dev/null; then
        systemctl enable nginx >/dev/null 2>&1
        if systemctl restart nginx 2>/dev/null; then
            log_success "Nginx decoy/reverse-proxy backend configured on 127.0.0.1:80"
        else
            log_warn "Nginx failed to restart — port 80 may be in use. Check: journalctl -u nginx"
        fi
    else
        log_warn "Nginx config test failed — check /etc/nginx/conf.d/whispera-ui.conf"
    fi
}

setup_telegram() {
    echo ""
    echo -e "${YELLOW}--- Setup Telegram Notifications ---${PLAIN}"
    echo "1. Create a bot via @BotFather in Telegram and copy the token."
    echo "2. Send /start to your bot, then get your user ID via @userinfobot."
    echo ""
    read -p "Enter Telegram Bot Token (from @BotFather, leave empty to cancel): " TG_TOKEN

    if [[ -z "$TG_TOKEN" ]]; then
        log_warn "Cancelled."
        return
    fi

    read -p "Enter your Telegram User ID (numbers only): " TG_ID

    if [[ -z "$TG_ID" ]]; then
        log_warn "Cancelled."
        return
    fi

    if ! [[ "$TG_ID" =~ ^-?[0-9]+$ ]]; then
        log_err "Invalid Telegram ID: must be a number (e.g. 123456789). Got: $TG_ID"
        return
    fi

    if [[ ! -f "$CONF_PATH/config.yaml" ]]; then
        log_err "Config file not found!"
        return
    fi

    log_info "Updating config..."
    sed -i "s|admin_id: .*|admin_id: $TG_ID|" "$CONF_PATH/config.yaml"
    sed -i "s|chat_id: .*|chat_id: \"$TG_ID\"|" "$CONF_PATH/config.yaml"
    sed -i "s|token: \"YOUR_TELEGRAM_BOT_TOKEN\"|token: \"$TG_TOKEN\"|g" "$CONF_PATH/config.yaml"
    sed -i "/^bot:/,/^[^ ]/ s|enabled: false|enabled: true|" "$CONF_PATH/config.yaml"
    sed -i "/^notifications:/,/^[^ ]/ s|enabled: false|enabled: true|" "$CONF_PATH/config.yaml"

    log_info "Testing bot connection..."
    local TEST_RESULT=$(curl -s "https://api.telegram.org/bot${TG_TOKEN}/getMe" 2>/dev/null)
    if echo "$TEST_RESULT" | grep -q '"ok":true'; then
        local BOT_NAME=$(echo "$TEST_RESULT" | grep -o '"first_name":"[^"]*"' | cut -d'"' -f4)
        log_success "Bot connected: $BOT_NAME"
    else
        log_warn "Could not verify bot token. Check the token and try again."
    fi

    log_info "Restarting Whispera..."
    refresh_config
    systemctl restart whispera
    log_success "Telegram notifications enabled for ID $TG_ID"
}

gen_bridge_ssh_otp() {
    log_info "Generating one-time SSH access code for bridge..."

    local TTL=${1:-3600}
    local KEY_DIR=$(mktemp -d)
    local KEY_FILE="$KEY_DIR/bridge_otp"

    ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "whispera-bridge-otp-$(date +%s)" -q

    local PUB_KEY=$(cat "$KEY_FILE.pub")
    local PRIV_KEY=$(cat "$KEY_FILE")
    local EXPIRE_AT=$(date -d "+${TTL} seconds" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v "+${TTL}S" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "in ${TTL}s")
    local MARKER="whispera-bridge-otp-$(date +%s)"

    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    echo "${PUB_KEY} ${MARKER}" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys

    local CLEANUP_SCRIPT="/tmp/whispera-otp-${MARKER}.sh"
    cat > "$CLEANUP_SCRIPT" <<CLEANSCRIPT
sed -i "/${MARKER}/d" ~/.ssh/authorized_keys
rm -f "$CLEANUP_SCRIPT"
CLEANSCRIPT
    chmod +x "$CLEANUP_SCRIPT"
    local SCHEDULED=0

    if command -v at &>/dev/null; then
        if systemctl is-active --quiet atd 2>/dev/null || service atd status &>/dev/null 2>&1 || pgrep -x atd &>/dev/null; then
            echo "bash $CLEANUP_SCRIPT" | at "now + $(( TTL / 60 + 1 )) minutes" 2>/dev/null && SCHEDULED=1
        fi
    fi

    if [[ "$SCHEDULED" -eq 0 ]] && command -v crontab &>/dev/null; then
        local CRON_TIME
        CRON_TIME=$(date -d "+$(( TTL / 60 + 1 )) minutes" '+%M %H %d %m *' 2>/dev/null \
                 || date -v "+$(( TTL / 60 + 1 ))M" '+%M %H %d %m *' 2>/dev/null)
        if [[ -n "$CRON_TIME" ]]; then
            (crontab -l 2>/dev/null | grep -v "$CLEANUP_SCRIPT"; \
             echo "$CRON_TIME bash $CLEANUP_SCRIPT") | crontab - 2>/dev/null && SCHEDULED=1
        fi
    fi

    if [[ "$SCHEDULED" -eq 0 ]]; then
        nohup bash -c "sleep ${TTL}; bash $CLEANUP_SCRIPT" </dev/null >/dev/null 2>&1 &
        log_warn "at/cron unavailable — using background process (key removed in ${TTL}s if server stays up)"
    fi

    rm -rf "$KEY_DIR"

    echo ""
    echo -e "${YELLOW}┌─── One-time SSH key (valid until: ${EXPIRE_AT}) ───────────────────────────────┐${PLAIN}"
    echo -e "${YELLOW}│ Expires automatically. Use ONCE to set up the bridge, then key is removed.   │${PLAIN}"
    echo -e "${YELLOW}└───────────────────────────────────────────────────────────────────────────────┘${PLAIN}"
    echo ""
    echo -e "${GREEN}Paste this private key into a file on the bridge server:${PLAIN}"
    echo ""
    echo "$PRIV_KEY"
    echo ""
    local SRV_IP=$(get_public_ip)
    echo -e "${GREEN}SSH command to use on the bridge server:${PLAIN}"
    echo -e "  ssh -i /tmp/bridge_key -o StrictHostKeyChecking=no root@${SRV_IP}"
    echo ""
    log_success "Key added to authorized_keys. It will self-remove after ${TTL}s."
}

setup_backups() {
    log_info "Setting up daily database backups..."
    
    if [[ ! -f "$CONF_PATH/postgres.env" ]]; then
        log_warn "PostgreSQL credentials not found. Installing PostgreSQL first..."
        setup_postgres
    fi
    
    cat > /usr/local/bin/whispera-backup <<'BACKUPEOF'
BACKUP_DIR="/var/backups/whispera"
RETENTION_DAYS=7
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/whispera/backup.log"
CONF_PATH="/etc/whispera"

mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

DB_URL=""
if [[ -f "$CONF_PATH/config.yaml" ]]; then
    DB_URL=$(grep -E '^\s*postgres_url:' "$CONF_PATH/config.yaml" | head -1 | sed 's/.*postgres_url:\s*["\x27]\?\([^"'\''[:space:]]*\)["\x27]\?.*/\1/')
fi
if [[ -z "$DB_URL" && -f "$CONF_PATH/postgres.env" ]]; then
    source "$CONF_PATH/postgres.env"
    DB_URL="${POSTGRES_URL:-postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost/${POSTGRES_DB}}"
fi
if [[ -z "$DB_URL" ]]; then
    log "ERROR: No database URL found in config.yaml or postgres.env"
    exit 1
fi

export PGPASSWORD=$(echo "$DB_URL" | grep -oP '://[^:]+:\K[^@]+')
PG_USER=$(echo "$DB_URL" | grep -oP '://\K[^:]+')
PG_HOST=$(echo "$DB_URL" | grep -oP '@\K[^:/]+')
PG_PORT=$(echo "$DB_URL" | grep -oP '@[^/]+:\K[0-9]+' || echo "5432")
PG_DB=$(echo "$DB_URL" | grep -oP '/\K[^?]+$')

FILENAME="$BACKUP_DIR/whispera_${DATE}.sql.gz"
log "Backup → $FILENAME (db=$PG_DB host=$PG_HOST)"

if ! command -v pg_dump &>/dev/null; then
    log "ERROR: pg_dump not found"
    exit 1
fi

if pg_dump -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" | gzip > "$FILENAME"; then
    SIZE=$(du -h "$FILENAME" | cut -f1)
    log "OK: $SIZE"
else
    log "FAILED"
    rm -f "$FILENAME"
    exit 1
fi

find "$BACKUP_DIR" -name "whispera_*.sql.gz" -mtime +"$RETENTION_DAYS" -delete
KEPT=$(ls -1 "$BACKUP_DIR"/whispera_*.sql.gz 2>/dev/null | wc -l)
log "Retention: kept $KEPT backups (${RETENTION_DAYS}d)"
BACKUPEOF

    chmod +x /usr/local/bin/whispera-backup
    
    if ! crontab -l 2>/dev/null | grep -q "whispera-backup"; then
        (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/whispera-backup >> /var/log/whispera/backup.log 2>&1") | crontab -
    fi
    
    log_success "Backups scheduled daily at 03:00"
    log_info "Backup location: /var/backups/whispera"
}

show_extras_menu() {
    local SEP
    SEP=$(printf '═%.0s' {1..62})
    _row() { echo -e "${BLUE}║${PLAIN} $(printf '%-60s' "$1") ${BLUE}║${PLAIN}"; }

    while true; do
        clear

        local SRV_IP=$(get_public_ip)
        local ADMIN_PASS=$(cat "$CONF_PATH/admin.pass" 2>/dev/null)
        echo ""
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${PLAIN}"
        echo -e "${GREEN} WEB PANEL${PLAIN}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${PLAIN}"
        echo -e "  URL:      ${BLUE}https://${SRV_IP}/${PLAIN}"
        echo -e "  User:     ${BLUE}admin${PLAIN}"
        echo -e "  Password: ${BLUE}${ADMIN_PASS}${PLAIN}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${PLAIN}"

        local BRIDGE_TOKEN=$(cat "$CONF_PATH/bridge.token" 2>/dev/null)

        echo ""
        echo -e "${BLUE}╔${SEP}╗${PLAIN}"
        _row "          WHISPERA MANAGEMENT MENU"
        _row "  Config: /etc/whispera/config.yaml"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  OPTIONAL EXTRAS"
        _row "  1.  BBR           - Faster TCP (recommended)"
        _row "  2.  WARP          - Hide server IP via Cloudflare"
        _row "  3.  Fail2ban      - Protect SSH from brute-force"
        _row "  4.  Swap          - Add 2GB swap (for low-RAM servers)"
        _row "  5.  Optimize      - Tune sysctl for high performance"
        _row "  6.  Auto-update   - Daily auto-update from GitHub"
        _row "  7.  SSH Hardening - Disable password auth (keys only)"
        _row "  8.  Redis         - Session cache for persistence"
        _row "  9.  PostgreSQL    - User accounts, traffic, billing"
        _row " 10.  Telegram      - Configure notifications"
        _row " 11.  Backups       - Daily database backups"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  SERVICE MANAGEMENT"
        _row " 12.  Start         - Start Whispera service"
        _row " 13.  Stop          - Stop Whispera service"
        _row " 14.  Restart       - Restart Whispera service"
        _row " 15.  Status        - Check service status"
        _row " 16.  View Logs     - Watch live logs"
        _row " 17.  Edit Config   - Modify config.yaml"
        _row " 18.  Update        - Update"
        _row " 19.  Change pass   - Generate a new password"
        _row "  0.  Exit"
        echo -e "${BLUE}╚${SEP}╝${PLAIN}"
        echo ""

        read -rp "  Select option: " choice
        case $choice in
            1) setup_bbr ;;
            2) setup_warp ;;
            3) setup_fail2ban ;;
            4) setup_swap ;;
            5) setup_sysctl ;;
            6) setup_autoupdate ;;
            7) setup_ssh_hardening ;;
            8) setup_redis ;;
            9) setup_postgres ;;
            10) setup_telegram ;;
            11) setup_backups ;;
            12) systemctl start whispera && log_success "Service started" || log_err "Failed to start service" ;;
            13) systemctl stop whispera && log_success "Service stopped" || log_err "Failed to stop service" ;;
            14) systemctl restart whispera && log_success "Service restarted" || log_err "Failed to restart service" ;;
            15) systemctl status whispera ;;
            16) journalctl -u whispera -f ;;
            17) ${EDITOR:-nano} /etc/whispera/config.yaml; refresh_config ;;
            18) bash <(curl -sL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/update.sh) ;;
            19)
                read -rp "  New password (leave empty to generate): " NEW_PASS
                if [[ -z "$NEW_PASS" ]]; then
                    NEW_PASS=$(gen_password 20)
                    echo -e "  Generated password: ${BLUE}${NEW_PASS}${PLAIN}"
                fi
                echo "$NEW_PASS" > "$CONF_PATH/admin.pass"
                chmod 600 "$CONF_PATH/admin.pass"
                nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
                log_success "Panel password updated. User: admin / Password: ${NEW_PASS}"
                ;;
            0|"") log_info "Exiting menu."; break ;;
            *) log_warn "Invalid option: $choice" ;;
        esac

        if [[ "$choice" != "0" ]] && [[ -n "$choice" ]]; then
            echo ""
            read -rp "  Press Enter to return to menu..."
        fi
    done
}


_verify_panel_archive() {
    local archive="$1"       # path to panel-release.tar.gz
    local sums_url="$2"      # URL to SHA256SUMS

    local bytes
    bytes=$(stat -c%s "$archive" 2>/dev/null || stat -f%z "$archive" 2>/dev/null || echo 0)
    if [[ "$bytes" -lt 524288 ]]; then
        log_err "Panel archive is suspiciously small (${bytes} bytes < 512 KB) — refusing to install"
        return 1
    fi

    if [[ -n "$sums_url" ]]; then
        local sums_file
        sums_file=$(mktemp)
        if curl -sL -o "$sums_file" "$sums_url" && [[ -s "$sums_file" ]]; then
            local expected_hash
            expected_hash=$(grep "whispera-panel.tar.gz" "$sums_file" | awk '{print $1}')
            if [[ -n "$expected_hash" ]]; then
                local actual_hash
                actual_hash=$(sha256sum "$archive" | awk '{print $1}')
                if [[ "$actual_hash" != "$expected_hash" ]]; then
                    log_err "Panel archive SHA256 mismatch!"
                    log_err "  Expected: $expected_hash"
                    log_err "  Actual:   $actual_hash"
                    rm -f "$sums_file"
                    return 1
                fi
                log_info "Panel archive SHA256 verified ✓"
            else
                log_warn "No entry for whispera-panel.tar.gz in SHA256SUMS — skipping hash check"
            fi
        else
            log_warn "Could not download SHA256SUMS — skipping hash verification"
        fi
        rm -f "$sums_file"
    fi
    return 0
}


do_update() {
    trap 'systemctl is-active --quiet whispera 2>/dev/null || { systemctl daemon-reload 2>/dev/null; systemctl start whispera 2>/dev/null || true; }' EXIT

    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR" || exit 1

    if command -v whispera-backup &>/dev/null; then
        log_info "Creating pre-update backup..."
        whispera-backup || log_warn "Backup failed, continuing anyway..."
    fi

    if [[ -d ".git" ]]; then
        log_info "Updating source code..."
        git config --global --add safe.directory "$(pwd)" 2>/dev/null || true
        git fetch origin $BRANCH --quiet
        git reset --hard origin/$BRANCH --quiet
    fi

    log_info "Creating backup of current version..."
    cp "$BIN_PATH/whispera" "$BIN_PATH/whispera.bak" 2>/dev/null || true
    if [[ -d "$DAT_PATH/panel" ]]; then
        rm -rf "$DAT_PATH/panel.bak"
        cp -r "$DAT_PATH/panel" "$DAT_PATH/panel.bak"
    fi

    log_info "Updating Whispera server..."
    export PATH=$PATH:/usr/local/go/bin
    rm -f whispera-server

    local ARCH="amd64"
    [[ $(uname -m) == "aarch64" ]] && ARCH="arm64"

    log_info "Fetching latest release info..."
    local RELEASE_JSON
    RELEASE_JSON=$(curl -s https://api.github.com/repos/Jalaveyan/Whispera/releases/latest)

    log_info "Downloading latest release from GitHub..."
    local DIRECT_URL="https://github.com/Jalaveyan/Whispera/releases/latest/download/whispera-server-linux-${ARCH}.tar.gz"

    local BIN_FOUND=false

    if curl -fL --retry 3 --retry-delay 2 -o whispera-server.tar.gz "$DIRECT_URL" 2>/dev/null; then
        if tar -xzf whispera-server.tar.gz 2>/dev/null; then
            rm -f whispera-server.tar.gz
            if [[ -f "whispera-server" ]]; then
                BIN_FOUND=true
                log_success "Update downloaded successfully"
            fi
        fi
    fi

    if [[ "$BIN_FOUND" != "true" ]]; then
        log_warn "Direct download failed, trying GitHub API..."
        local DOWNLOAD_URL
        DOWNLOAD_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "whispera-server-linux-$ARCH.tar.gz" | head -n 1 | cut -d '"' -f 4)
        if [[ -n "$DOWNLOAD_URL" ]]; then
            if curl -fL --retry 3 -o whispera-server.tar.gz "$DOWNLOAD_URL" 2>/dev/null; then
                if tar -xzf whispera-server.tar.gz 2>/dev/null; then
                    rm -f whispera-server.tar.gz
                    [[ -f "whispera-server" ]] && BIN_FOUND=true && log_success "Update downloaded via API"
                fi
            fi
        fi
    fi

    if [[ "$BIN_FOUND" != "true" ]]; then
        log_info "Release download failed, building from source..."

        if [[ -d "$WORK_DIR/.git" ]]; then
            log_info "Pulling from GitHub..."
            cd "$WORK_DIR"
            git config --global --add safe.directory "$WORK_DIR" 2>/dev/null || true
            git fetch origin $BRANCH --quiet
            git reset --hard origin/$BRANCH --quiet
        fi

        go build -trimpath -ldflags "-w -s" -o whispera-server ./app/server || true
    fi
    
    if [[ ! -f "whispera-server" ]]; then
        log_err "Build failed!"
        exit 1
    fi
    
    log_info "Stopping service..."
    systemctl stop whispera 2>/dev/null || true
    for _ in 1 2 3 4; do
        if ! pgrep -x whispera >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
    if pgrep -x whispera >/dev/null 2>&1; then
        pkill -9 -x whispera 2>/dev/null || true
        sleep 0.3
    fi
    if fuser "$BIN_PATH/whispera" >/dev/null 2>&1; then
        fuser -k "$BIN_PATH/whispera" 2>/dev/null || true
        sleep 0.3
    fi

    log_info "Installing binary..."
    cp whispera-server "$BIN_PATH/whispera"
    chmod +x "$BIN_PATH/whispera"
    
    if [[ -d "web" ]]; then
        log_info "Updating Web UI..."
        mkdir -p "$DAT_PATH/web"
        cp -r web/* "$DAT_PATH/web/"
    fi

    if [[ -f "scripts/install-bridge.sh" ]]; then
        mkdir -p "/opt/whispera/scripts"
        cp "scripts/install-bridge.sh" "/opt/whispera/scripts/install-bridge.sh" 2>/dev/null || true
        chmod +x "/opt/whispera/scripts/install-bridge.sh"
        log_info "Bridge install script deployed to /opt/whispera/scripts/"
    fi

    if [[ -f /etc/systemd/system/whispera-panel.service ]]; then
        log_info "Removing legacy whispera-panel (Node) service — panel is static now"
        systemctl stop whispera-panel 2>/dev/null || true
        systemctl disable whispera-panel 2>/dev/null || true
        rm -f /etc/systemd/system/whispera-panel.service
        systemctl daemon-reload
    fi
    if [[ -d "panel/public" ]]; then
        log_info "Updating panel static files..."
        rm -rf "$DAT_PATH/panel/public"
        mkdir -p "$DAT_PATH/panel"
        cp -r panel/public "$DAT_PATH/panel/public"
        mkdir -p "$DAT_PATH/panel/public/uploads"
        chmod -R a+rX "$DAT_PATH/panel/public"
        chown -R whispera:whispera "$DAT_PATH/panel" 2>/dev/null || true
        log_success "Panel static files updated"
    fi
    generate_panel_cert
    if ! grep -q "CAP_NET_ADMIN" /etc/systemd/system/whispera.service 2>/dev/null; then
        sed -i 's/AmbientCapabilities=CAP_NET_BIND_SERVICE$/AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN/' \
            /etc/systemd/system/whispera.service
        log_info "Added CAP_NET_ADMIN to whispera service"
    fi
    systemctl daemon-reload
    setup_nginx_proxy
    log_success "Panel updated (static)"

    
    mkdir -p /var/log/whispera
    chown whispera:whispera /var/log/whispera 2>/dev/null || true

    if [[ ! -f /etc/sudoers.d/whispera-ufw ]]; then
        local UFW_BIN
        UFW_BIN=$(command -v ufw 2>/dev/null || echo /usr/sbin/ufw)
        echo "whispera ALL=(ALL) NOPASSWD: $UFW_BIN" > /etc/sudoers.d/whispera-ufw
        chmod 440 /etc/sudoers.d/whispera-ufw
        log_info "Configured sudo access for UFW"
    fi

    if ! grep -q "WHISPERA_MASK_LOGS" /etc/systemd/system/whispera.service; then
        sed -i '/\[Service\]/a Environment=WHISPERA_MASK_LOGS=false' /etc/systemd/system/whispera.service
        systemctl daemon-reload
    fi

    if ! grep -q "StandardOutput=append" /etc/systemd/system/whispera.service 2>/dev/null; then
        sed -i '/ReadWritePaths=.*/a StandardOutput=append:\/var\/log\/whispera\/whispera.log\nStandardError=append:\/var\/log\/whispera\/whispera.log' \
            /etc/systemd/system/whispera.service
        systemctl daemon-reload
        log_info "Enabled file logging for whispera service"
    fi

    if [[ -d "$DAT_PATH/panel" ]]; then
        mkdir -p "$DAT_PATH/panel/public/uploads"
        chown -R whispera:whispera "$DAT_PATH/panel/public" 2>/dev/null || true
    fi

    local SVC=/etc/systemd/system/whispera.service
    if [[ -f "$SVC" ]]; then
        local RELOAD=false
        if grep -q "^NoNewPrivileges=true" "$SVC"; then
            sed -i '/^NoNewPrivileges=true/d' "$SVC"
            RELOAD=true
            log_info "Removed NoNewPrivileges from whispera.service (required for UFW sudo)"
        fi
        if ! grep -q "CAP_NET_RAW" "$SVC"; then
            sed -i 's/AmbientCapabilities=\(.*\)/AmbientCapabilities=\1 CAP_NET_RAW/' "$SVC"
            RELOAD=true
        fi
        if ! grep -q "/etc/ufw" "$SVC"; then
            sed -i 's|ReadWritePaths=\(.*\)|ReadWritePaths=\1 /etc/ufw /lib/ufw /var/lib/ufw|' "$SVC"
            RELOAD=true
        fi
        if ! grep -q "$CONF_PATH" "$SVC"; then
            sed -i "s|ReadWritePaths=\(.*\)|ReadWritePaths=\1 $CONF_PATH|" "$SVC"
            RELOAD=true
            log_info "Added $CONF_PATH to ReadWritePaths in whispera.service"
        fi
        if ! grep -qE " /run( |$)" "$SVC"; then
            sed -i 's|ReadWritePaths=\(.*\)|ReadWritePaths=\1 /run /var/crash|' "$SVC"
            RELOAD=true
            log_info "Added /run to ReadWritePaths in whispera.service"
        fi
        if grep -q "/run/ufw.lock" "$SVC"; then
            sed -i 's| /run/ufw\.lock||g' "$SVC"
            RELOAD=true
        fi
        for directive in Type=notify WatchdogSec TimeoutStopSec TimeoutStartSec; do
            if grep -q "^${directive}" "$SVC"; then
                sed -i "/^${directive}/d" "$SVC"
                RELOAD=true
                log_info "Removed $directive from whispera.service"
            fi
        done
        if grep -q "^LimitNOFILE=" "$SVC"; then
            sed -i 's/^LimitNOFILE=.*/LimitNOFILE=infinity/' "$SVC"
            RELOAD=true
        fi
        if ! grep -q "EnvironmentFile=.*whispera.env" "$SVC"; then
            if [[ ! -f "$INTEGRITY_ENV_FILE" ]]; then
                local newkey
                newkey=$(openssl rand -hex 32 2>/dev/null)
                [[ -z "$newkey" ]] && newkey=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
                printf 'WHISPERA_INTEGRITY_KEY=%s\n' "$newkey" > "$INTEGRITY_ENV_FILE"
                chmod 600 "$INTEGRITY_ENV_FILE"
                chown whispera:whispera "$INTEGRITY_ENV_FILE" 2>/dev/null || true
            fi
            export WHISPERA_INTEGRITY_KEY="$(sed -n 's/^WHISPERA_INTEGRITY_KEY=//p' "$INTEGRITY_ENV_FILE" | head -n1)"
            sed -i "/^\[Service\]/a EnvironmentFile=-$INTEGRITY_ENV_FILE" "$SVC"
            refresh_config
            RELOAD=true
            log_info "Migrated whispera.service to persistent integrity key"
        fi
        if [[ "$RELOAD" == true ]]; then
            systemctl daemon-reload
            log_info "Updated whispera.service for UFW access"
        fi
    fi

    if [[ -d "/opt/whispera-ml" ]]; then
        log_info "Removing legacy ML repo at /opt/whispera-ml..."
        rm -rf "/opt/whispera-ml"
    fi
    log_info "ML engine is built into the main Whispera binary (no Python required)"
    if [[ -f /etc/systemd/system/whispera-ml.service ]]; then
        log_info "Removing legacy Python ML service..."
        systemctl stop whispera-ml 2>/dev/null || true
        systemctl disable whispera-ml 2>/dev/null || true
        rm -f /etc/systemd/system/whispera-ml.service
        systemctl daemon-reload
    fi
    _enable_ml_in_config
    _enable_chameleon_in_config

    if [[ -f "$CONF_PATH/config.yaml" ]]; then
        local MTD
        MTD=$(grep 'max_time_diff:' "$CONF_PATH/config.yaml" | awk '{print $2}' | tr -d '[:space:]')
        if [[ -n "$MTD" && "$MTD" -lt 1000 ]] 2>/dev/null; then
            log_warn "Config: max_time_diff=$MTD is too small (ms units). Updating to 300000 (5 min)..."
            sed -i "s/max_time_diff: $MTD/max_time_diff: 300000/" "$CONF_PATH/config.yaml"
            log_success "max_time_diff updated: $MTD -> 300000"
        fi

        local RELAY_COUNT
        RELAY_COUNT=$(grep -c "^relay:" "$CONF_PATH/config.yaml" 2>/dev/null || echo 0)
        if [[ "$RELAY_COUNT" -gt 1 ]]; then
            log_warn "Config: duplicate relay: blocks detected ($RELAY_COUNT). Merging..."
            awk '
            /^relay:/ { if (seen_relay) { skip=1; next } seen_relay=1 }
            skip && /^[^ ]/ && !/^relay:/ { skip=0 }
            !skip { print }
            ' "$CONF_PATH/config.yaml" > "$CONF_PATH/config.yaml.tmp" && \
                mv "$CONF_PATH/config.yaml.tmp" "$CONF_PATH/config.yaml"
            log_success "relay: blocks merged"
        fi

        load_integrity_key
        "$BIN_PATH/whispera" update-checksum "$CONF_PATH/config.yaml" && log_info "Config checksum updated" || log_warn "Config checksum update failed (non-fatal)"
    fi

    setup_nginx_proxy
    log_info "Starting service..."
    systemctl daemon-reload
    if ! systemctl start whispera; then
        log_err "Whispera service failed to start after update!"
        journalctl -u whispera -n 20 --no-pager 2>/dev/null || true
        restore
    fi

    sleep 3
    if ! systemctl is-active --quiet whispera; then
        log_err "Whispera service started but is not active after 3s!"
        journalctl -u whispera -n 20 --no-pager 2>/dev/null || true
        restore
    fi

    PUBLIC_KEY=$(cat "$CONF_PATH/server.pub" 2>/dev/null)
    SERVER_IP=$(get_public_ip)
    
    echo ""
    log_success "Whispera updated successfully!"
    echo -e "  Config:         ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
    echo -e "  Web Panel:      ${GREEN}https://whispera-ui/${PLAIN}"
    echo -e "  ${GREEN}${SERVER_IP} whispera-ui${PLAIN}  → в файл /etc/hosts (Linux/Mac) или C:\\Windows\\System32\\drivers\\etc\\hosts (Windows)"
    
    local ADMIN_PASS_UPD=$(cat "$CONF_PATH/admin.pass" 2>/dev/null)
    if [[ -n "$ADMIN_PASS_UPD" ]]; then
        echo ""
        echo -e "${GREEN}================================================================${PLAIN}"
        echo -e "${GREEN} WEB PANEL                                                      ${PLAIN}"
        echo -e "${GREEN}================================================================${PLAIN}"
        echo -e "  URL:      ${BLUE}https://${SERVER_IP}/${PLAIN}"
        echo -e "  User:     ${BLUE}admin${PLAIN}"
        echo -e "  Password: ${BLUE}${ADMIN_PASS_UPD}${PLAIN}"
        echo -e "${GREEN}================================================================${PLAIN}"
    fi
    echo ""
    
    show_extras_menu
}


check_root
check_os

case "${1:-}" in
    bbr) setup_bbr ;;
    warp) setup_warp ;;
    fail2ban) setup_fail2ban ;;
    swap) setup_swap ;;
    optimize) setup_sysctl ;;
    autoupdate) setup_autoupdate ;;
    harden) setup_ssh_hardening ;;
    redis) setup_redis ;;
    postgres) setup_postgres ;;
    telegram) setup_telegram ;;
    backups) setup_backups ;;
    all) setup_bbr; setup_sysctl; setup_redis; setup_postgres; setup_backups ;;
    extras) show_extras_menu ;;
    help|--help|-h)
        echo "Whispera Update Script v2.1"
        echo ""
        echo "Usage: ./update.sh [command]"
        echo ""
        echo "Commands:"
        echo "  (no args)   Update Whispera"
        echo "  extras      Show extras menu"
        echo "  all         Install BBR + sysctl + Redis + PostgreSQL"
        echo ""
        echo "Individual extras:"
        echo "  bbr         Enable BBR (faster TCP)"
        echo "  warp        Cloudflare WARP (hide IP)"
        echo "  fail2ban    Protect SSH"
        echo "  swap        Create 2GB swap"
        echo "  optimize    Tune sysctl"
        echo "  autoupdate  Enable daily updates"
        echo "  harden      SSH hardening"
        echo "  redis       Install Redis cache"
        echo "  postgres    Install PostgreSQL database"
        ;;
    *)
        do_update
        ;;
esac
