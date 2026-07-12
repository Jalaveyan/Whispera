#!/bin/bash


REPO_URL="https://github.com/nekoskin/whispera.git"
BRANCH="main"
WORK_DIR="/opt/whispera"
DAT_PATH="/usr/local/share/whispera"
CONF_PATH="/etc/whispera"
BIN_PATH="/usr/local/bin"
LOG_PATH="/var/log/whispera"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'


log_info() { echo -e "${BLUE}[INFO]${PLAIN} $1"; }
log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERR]${PLAIN} $1"; }

WHISPERA_LIB_URL="https://raw.githubusercontent.com/nekoskin/whispera/main/scripts/lib.sh"
__wsp_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)"
if [[ -n "$__wsp_script_dir" && -f "$__wsp_script_dir/scripts/lib.sh" ]]; then
    source "$__wsp_script_dir/scripts/lib.sh"
else
    __wsp_lib_tmp="$(mktemp)"
    if curl -fsSL "$WHISPERA_LIB_URL" -o "$__wsp_lib_tmp"; then
        source "$__wsp_lib_tmp"
    else
        echo "Failed to download lib.sh from $WHISPERA_LIB_URL" >&2
        rm -f "$__wsp_lib_tmp"
        exit 1
    fi
    rm -f "$__wsp_lib_tmp"
fi

INTEGRITY_ENV_FILE="$CONF_PATH/whispera.env"

ensure_integrity_key() {
    if [[ -z "$WHISPERA_INTEGRITY_KEY" && -f "$INTEGRITY_ENV_FILE" ]]; then
        local existing
        existing=$(sed -n 's/^WHISPERA_INTEGRITY_KEY=//p' "$INTEGRITY_ENV_FILE" 2>/dev/null | head -n1)
        [[ -n "$existing" ]] && export WHISPERA_INTEGRITY_KEY="$existing"
    fi
    if [[ -z "$WHISPERA_INTEGRITY_KEY" ]]; then
        local k
        k=$(openssl rand -hex 32 2>/dev/null)
        [[ -z "$k" ]] && k=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
        export WHISPERA_INTEGRITY_KEY="$k"
        mkdir -p "$CONF_PATH"
        printf 'WHISPERA_INTEGRITY_KEY=%s\n' "$k" > "$INTEGRITY_ENV_FILE"
        chmod 600 "$INTEGRITY_ENV_FILE"
        chown whispera:whispera "$INTEGRITY_ENV_FILE" 2>/dev/null || true
        log_info "Generated persistent integrity key ($INTEGRITY_ENV_FILE)"
    fi
}

refresh_config() {
    local cfg="${1:-$CONF_PATH/config.yaml}"
    if [[ ! -f "$cfg" ]]; then return; fi
    ensure_integrity_key
    local bin
    bin=$(command -v whispera 2>/dev/null) || bin="$BIN_PATH/whispera"
    if [[ ! -x "$bin" ]]; then
        log_warn "whispera binary not found ($bin) — checksum NOT updated; integrity check may fail on restart"
        return
    fi
    if "$bin" update-checksum "$cfg" >/dev/null 2>&1; then
        log_info "Config checksum updated"
    else
        log_warn "update-checksum failed for $cfg — integrity check may fail on restart"
    fi
}

print_logo() {
    echo -e "${BLUE}"
    echo "██╗    ██╗██╗  ██╗██╗███████╗██████╗ ███████╗██████╗  █████╗"
    echo "██║    ██║██║  ██║██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗"
    echo "██║ █╗ ██║███████║██║███████╗██████╔╝█████╗  ██████╔╝███████║"
    echo "██║███╗██║██╔══██║██║╚════██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║"
    echo "╚███╔███╔╝██║  ██║██║███████║██║     ███████╗██║  ██║██║  ██║"
    echo " ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝"
    echo ":: Whispera Installer ::"
    echo -e "${PLAIN}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "This script must be run as root!"
        exit 1
    fi
}

has_systemd() {
    [[ -d /run/systemd/system ]] || { command -v systemctl &>/dev/null && systemctl --version &>/dev/null; }
}

make_service_user() {
    local user="$1"
    if id -u "$user" &>/dev/null; then
        return 0
    fi
    local nologin
    nologin=$(command -v nologin 2>/dev/null || true)
    if [[ -z "$nologin" ]]; then
        for p in /usr/sbin/nologin /sbin/nologin /bin/false; do
            [[ -x "$p" ]] && nologin="$p" && break
        done
    fi
    [[ -z "$nologin" ]] && nologin=/bin/false
    if command -v useradd &>/dev/null; then
        useradd --system --no-create-home --shell "$nologin" "$user" 2>/dev/null || \
        useradd -r -M -s "$nologin" "$user" 2>/dev/null || true
    elif command -v adduser &>/dev/null; then
        adduser -S -D -H -s "$nologin" "$user" 2>/dev/null || \
        adduser --system --no-create-home --disabled-password "$user" 2>/dev/null || true
    fi
    if id -u "$user" &>/dev/null; then
        log_info "Created system user '$user'"
    else
        log_warn "Could not create system user '$user'"
    fi
}

fw_allow_port() {
    local port="$1" proto="${2:-tcp}"
    if command -v ufw &>/dev/null && ufw status &>/dev/null; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    elif command -v iptables &>/dev/null; then
        iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
}

fw_deny_port() {
    local port="$1" proto="${2:-tcp}"
    if command -v ufw &>/dev/null && ufw status &>/dev/null; then
        ufw deny "${port}/${proto}" >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; then
        firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    elif command -v iptables &>/dev/null; then
        iptables -C INPUT -p "$proto" --dport "$port" -j DROP 2>/dev/null || \
        iptables -A INPUT -p "$proto" --dport "$port" -j DROP 2>/dev/null || true
    fi
}

install_dependencies() {
    log_info "Installing dependencies..."

    case $RELEASE in
        ubuntu|debian)
            apt-get update
            apt-get install -y curl git wget tar unzip openssl nano jq bc net-tools iproute2
            ;;
        centos|fedora|almalinux|rocky)
            local DNF=dnf
            command -v dnf &>/dev/null || DNF=yum
            $DNF install -y epel-release || true
            $DNF install -y curl git wget tar unzip openssl nano jq bc net-tools iproute
            ;;
        alpine)
            apk add --no-cache curl git wget tar unzip openssl nano jq bc iproute2
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm curl git wget tar unzip openssl nano jq bc net-tools iproute2
            ;;
        opensuse*|sles)
            zypper --non-interactive install -y curl git wget tar unzip openssl nano jq bc net-tools iproute2
            ;;
        *)
            log_warn "Unknown OS '$RELEASE' — attempting generic install"
            if command -v apt-get &>/dev/null; then
                apt-get update; apt-get install -y curl git wget tar unzip openssl jq bc
            elif command -v dnf &>/dev/null; then
                dnf install -y curl git wget tar unzip openssl jq bc
            elif command -v yum &>/dev/null; then
                yum install -y curl git wget tar unzip openssl jq bc
            elif command -v apk &>/dev/null; then
                apk add --no-cache curl git wget tar unzip openssl jq bc
            elif command -v pacman &>/dev/null; then
                pacman -Sy --noconfirm curl git wget tar unzip openssl jq bc
            elif command -v zypper &>/dev/null; then
                zypper --non-interactive install -y curl git wget tar unzip openssl jq bc
            else
                log_err "No supported package manager found"
                exit 1
            fi
            ;;
    esac

    if command -v timedatectl &>/dev/null; then
        log_info "Synchronizing system time..."
        timedatectl set-ntp on || true
    fi

    log_success "Dependencies installed"
}


install_go() {
    if command -v go &>/dev/null; then
        local GO_VER=$(go version | awk '{print $3}')
        log_info "Go already installed: $GO_VER"
        return
    fi
    
    log_info "Installing Go..."
    local GO_V=$(curl -s https://go.dev/dl/?mode=json 2>/dev/null | grep -o 'go[0-9.]*' | head -n1)
    
    if [[ -z "$GO_V" ]]; then
        GO_V="go1.24.3"
    fi
    
    wget -q "https://go.dev/dl/${GO_V}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    
    export PATH=$PATH:/usr/local/go/bin
    export PATH=$PATH:$HOME/go/bin
    
    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        echo 'export PATH=$PATH:$HOME/go/bin' >> /etc/profile
    fi
    
    log_success "Go installed: $GO_V"
}

setup_bbr() {
    log_info "Enabling BBR TCP congestion control..."
    
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_info "BBR already enabled"
        return
    fi
    
    local KERNEL_VER=$(uname -r | cut -d. -f1-2)
    local KERNEL_MAJOR=$(echo $KERNEL_VER | cut -d. -f1)
    local KERNEL_MINOR=$(echo $KERNEL_VER | cut -d. -f2)
    
    if [[ $KERNEL_MAJOR -lt 4 ]] || [[ $KERNEL_MAJOR -eq 4 && $KERNEL_MINOR -lt 9 ]]; then
        log_warn "Kernel $KERNEL_VER too old for BBR (requires 4.9+), skipping"
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
        log_warn "BBR enable failed, kernel may not support it"
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
        ubuntu|debian)
            apt-get install -y fail2ban >/dev/null 2>&1
            ;;
        centos|fedora|almalinux|rocky)
            yum install -y fail2ban >/dev/null 2>&1
            ;;
        *)
            log_warn "Fail2ban not supported on $RELEASE"
            return
            ;;
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
        log_success "Fail2ban installed and running (sshd + whispera + panel jails)"
        log_info "Config: /etc/fail2ban/jail.local"
    else
        log_warn "Fail2ban installed but not running. Check: journalctl -u fail2ban"
    fi
}

setup_postgres() {
    log_info "Setting up PostgreSQL..."
    
    if command -v psql &>/dev/null && systemctl is-active --quiet postgresql 2>/dev/null; then
        if sudo -u postgres psql -lqt 2>/dev/null | grep -q whispera; then
            log_success "PostgreSQL already installed with whispera database"
            log_info "Connection: postgresql://whispera@localhost/whispera"
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
        alpine)
            apk add postgresql >/dev/null 2>&1
            ;;
        *)
            log_warn "PostgreSQL installation not supported on $RELEASE"
            return
            ;;
    esac
    
    if ! command -v psql &>/dev/null; then
        log_warn "PostgreSQL installation failed"
        return
    fi
    
    systemctl enable postgresql >/dev/null 2>&1
    systemctl start postgresql >/dev/null 2>&1
    
    sleep 2
    
    local PG_CONF_DIR=""
    for dir in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data; do
        if [[ -f "$dir/pg_hba.conf" ]]; then
            PG_CONF_DIR="$dir"
            break
        fi
    done
    
    if [[ -z "$PG_CONF_DIR" ]]; then
        PG_CONF_DIR=$(sudo -u postgres psql -t -c "SHOW config_file" 2>/dev/null | xargs dirname 2>/dev/null)
    fi
    
    if [[ -n "$PG_CONF_DIR" ]] && [[ -f "$PG_CONF_DIR/pg_hba.conf" ]]; then
        log_info "Configuring pg_hba.conf for local TCP auth..."
        cp "$PG_CONF_DIR/pg_hba.conf" "$PG_CONF_DIR/pg_hba.conf.bak"
        
        if ! grep -q "whispera" "$PG_CONF_DIR/pg_hba.conf"; then
            sed -i '/^# IPv4 local connections/a host    whispera        whispera        127.0.0.1/32            scram-sha-256' "$PG_CONF_DIR/pg_hba.conf" 2>/dev/null || true
        fi
        
        if grep -q "^local.*all.*all.*peer" "$PG_CONF_DIR/pg_hba.conf"; then
            sed -i 's/^local\s\+all\s\+all\s\+peer/local   all             all                                     md5/' "$PG_CONF_DIR/pg_hba.conf"
        fi
        
        sed -i 's/^\(host\s\+all\s\+all\s\+127\.0\.0\.1\/32\s\+\)ident/\1scram-sha-256/' "$PG_CONF_DIR/pg_hba.conf" 2>/dev/null || true
        sed -i 's/^\(host\s\+all\s\+all\s\+::1\/128\s\+\)ident/\1scram-sha-256/' "$PG_CONF_DIR/pg_hba.conf" 2>/dev/null || true
        
        if grep -q "0\.0\.0\.0/0" "$PG_CONF_DIR/pg_hba.conf"; then
            sed -i '/0\.0\.0\.0\/0/d' "$PG_CONF_DIR/pg_hba.conf"
        fi
        
        log_success "pg_hba.conf: local-only password auth (no remote access)"
    fi
    
    if [[ -n "$PG_CONF_DIR" ]] && [[ -f "$PG_CONF_DIR/postgresql.conf" ]]; then
        if grep -q "^#listen_addresses" "$PG_CONF_DIR/postgresql.conf"; then
            sed -i "s/^#listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF_DIR/postgresql.conf"
        elif grep -q "^listen_addresses" "$PG_CONF_DIR/postgresql.conf"; then
            sed -i "s/^listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF_DIR/postgresql.conf"
        fi
        
        log_success "postgresql.conf: listen_addresses = 'localhost' (secure)"
    fi
 
    systemctl restart postgresql >/dev/null 2>&1
    sleep 2
    
    local PG_PASS=$(gen_password 30)
    
    sudo -u postgres psql <<EOF >/dev/null 2>&1
CREATE USER whispera WITH PASSWORD '$PG_PASS';
CREATE DATABASE whispera OWNER whispera;
GRANT ALL PRIVILEGES ON DATABASE whispera TO whispera;
\q
EOF
    
    mkdir -p "$CONF_PATH"
    cat > "$CONF_PATH/postgres.env" <<EOF
POSTGRES_USER=whispera
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=whispera
POSTGRES_URL=postgresql://whispera:$PG_PASS@localhost/whispera
EOF
    chmod 600 "$CONF_PATH/postgres.env"
    
    fw_deny_port 5432 tcp
    
    if sudo -u postgres psql -lqt 2>/dev/null | grep -q whispera; then
        log_success "PostgreSQL installed and configured (local-only)"
        log_info "Credentials saved to: $CONF_PATH/postgres.env"
        echo ""
        log_info "DBeaver: use SSH tunnel to connect securely"
        echo "  SSH Host:     $(get_public_ip)"
        echo "  SSH Port:     22"
        echo "  SSH User:     root"
        echo "  DB Host:      127.0.0.1"
        echo "  DB Port:      5432"
        echo "  DB Name:      whispera"
        echo "  DB User:      whispera"
        echo "  DB Password:  (see $CONF_PATH/postgres.env)"
    else
        log_warn "PostgreSQL installed but database creation failed"
    fi
}

setup_swap() {
    log_info "Setting up Swap..."
    
    if swapon --show | grep -q "/"; then
        log_info "Swap already exists"
        swapon --show
        return
    fi
    
    local SWAP_SIZE="2G"
    
    fallocate -l $SWAP_SIZE /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    
    sysctl vm.swappiness=10 >/dev/null 2>&1
    grep -q "vm.swappiness" /etc/sysctl.conf || echo "vm.swappiness=10" >> /etc/sysctl.conf

    log_success "Swap $SWAP_SIZE created"
}

setup_sysctl() {
    log_info "Optimizing system settings..."

    cat > /etc/sysctl.d/99-whispera.conf <<'EOF'
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
fs.file-max = 1000000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
EOF

    sysctl --system >/dev/null 2>&1

    if ! grep -q "nofile 1000000" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf <<'EOF'
* soft nofile 1000000
* hard nofile 1000000
EOF
    fi

    log_success "System optimized"
}

setup_autoupdate() {
    log_info "Setting up auto-update..."

    cat > /etc/cron.daily/whispera-update <<'CRONEOF'
LOG="/var/log/whispera-update.log"
exec >> "$LOG" 2>&1
echo "=== $(date) ==="

ARCH="amd64"
[[ $(uname -m) == "aarch64" ]] && ARCH="arm64"
DIRECT_URL="https://github.com/nekoskin/whispera/releases/latest/download/whispera-server-linux-${ARCH}.tar.gz"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

if curl -fL --retry 3 --retry-delay 2 -o "$TMP_DIR/whispera.tar.gz" "$DIRECT_URL" 2>/dev/null; then
    if tar -xzf "$TMP_DIR/whispera.tar.gz" -C "$TMP_DIR" 2>/dev/null && [[ -f "$TMP_DIR/whispera-server" ]]; then
        systemctl stop whispera 2>/dev/null || true
        cp "$TMP_DIR/whispera-server" /usr/local/bin/whispera
        chmod +x /usr/local/bin/whispera
        chown -R whispera:whispera "$CONF_PATH" 2>/dev/null || true
        systemctl start whispera
        echo "Updated successfully"
    else
        echo "Extraction failed — keeping current binary"
    fi
else
    echo "Download failed — keeping current binary"
fi
CRONEOF
    chmod +x /etc/cron.daily/whispera-update

    log_success "Auto-update enabled (daily, downloads from GitHub Releases)"
}

setup_ssh_hardening() {
    log_info "Hardening SSH..."
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
    
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    
    
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    
    log_success "SSH hardened (password auth disabled)"
    log_warn "Make sure you have SSH key access before logging out!"
}


setup_backups() {
    log_info "Setting up daily database backups..."
    
    if [[ ! -f "$CONF_PATH/postgres.env" ]]; then
        log_warn "PostgreSQL credentials not found. Installing PostgreSQL first..."
        setup_postgres
    fi
    
    cat > /usr/local/bin/whispera-backup <<EOF
BACKUP_DIR="/var/backups/whispera"
RETENTION_DAYS=7
DATE=\$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/whispera/backup.log"

mkdir -p "\$BACKUP_DIR"
mkdir -p "\$(dirname "\$LOG_FILE")"

log() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" | tee -a "\$LOG_FILE"
}

if [ -f "$CONF_PATH/postgres.env" ]; then
    source $CONF_PATH/postgres.env
else
    log "Error: $CONF_PATH/postgres.env not found!"
    exit 1
fi

export PGPASSWORD=\$POSTGRES_PASSWORD

FILENAME="\$BACKUP_DIR/whispera_backup_\$DATE.sql.gz"
log "Starting backup: \$FILENAME"

if pg_dump -h localhost -U \$POSTGRES_USER -d \$POSTGRES_DB | gzip > "\$FILENAME"; then
    log "Backup created successfully: \$(du -h "\$FILENAME" | cut -f1)"
else
    log "Backup failed!"
    rm -f "\$FILENAME"
    exit 1
fi

ls -1t "\$BACKUP_DIR"/whispera_backup_*.sql.gz 2>/dev/null | tail -n +6 | xargs -r rm -f
EOF

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
        echo -e "${BLUE}╔${SEP}╗${PLAIN}"
        _row "          WHISPERA MANAGEMENT MENU"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  Config:     /etc/whispera/config.yaml"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  OPTIONAL EXTRAS"
        _row "  1.  BBR           - Faster TCP (recommended)"
        _row "  2.  WARP          - Hide server IP via Cloudflare"
        _row "  3.  Fail2ban      - Protect SSH from brute-force"
        _row "  4.  Swap          - Add 2GB swap (for low-RAM servers)"
        _row "  5.  Optimize      - Tune sysctl for high performance"
        _row "  6.  Auto-update   - Daily auto-update from GitHub"
        _row "  7.  SSH Hardening - Disable password auth (keys only)"
        _row "  8.  PostgreSQL    - User accounts, traffic, billing"
        _row "  9.  Telegram      - Configure notifications"
        _row " 10.  Backups       - Daily database backups"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  SERVICE MANAGEMENT"
        _row " 11.  Start         - Start Whispera service"
        _row " 12.  Stop          - Stop Whispera service"
        _row " 13.  Restart       - Restart Whispera service"
        _row " 14.  Status        - Check service status"
        _row " 15.  View Logs     - Watch live logs"
        _row " 16.  Edit Config   - Modify config.yaml"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row " 17.  Update        - Update Whispera from GitHub"
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
            8) setup_postgres ;;
            9) setup_telegram ;;
            10) setup_backups ;;
            a|A) setup_bbr; setup_sysctl; setup_postgres; setup_backups ;;
            11) systemctl start whispera && log_success "Service started" || log_err "Failed to start service" ;;
            12) systemctl stop whispera && log_success "Service stopped" || log_err "Failed to stop service" ;;
            13) systemctl restart whispera && log_success "Service restarted" || log_err "Failed to restart service" ;;
            14) systemctl status whispera ;;
            15) journalctl -u whispera -f ;;
            16) ${EDITOR:-nano} /etc/whispera/config.yaml; refresh_config ;;
            17)
                pkill -9 whispera 2>/dev/null
                bash <(curl -sL https://raw.githubusercontent.com/nekoskin/whispera/main/update.sh)
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

clone_or_update_repo() {
    log_info "Setting up Whispera source code..."
    
    mkdir -p "$WORK_DIR"
    
    if [[ -d "$WORK_DIR/.git" ]]; then
        log_info "Repository exists, updating..."
        cd "$WORK_DIR"
        git fetch origin "$BRANCH" --quiet
        git reset --hard "origin/$BRANCH" --quiet
    else
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        
        if [[ -f "$SCRIPT_DIR/app/server/main.go" ]]; then
            log_info "Installing from local source..."
            if [[ "$SCRIPT_DIR" != "$WORK_DIR" ]]; then
                rm -rf "$WORK_DIR"/*
                cp -r "$SCRIPT_DIR"/* "$WORK_DIR/"
            fi
        else
            log_info "Cloning repository..."
            rm -rf "$WORK_DIR"
            git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$WORK_DIR" --quiet
        fi
    fi
    
    cd "$WORK_DIR"
    log_success "Source code ready in $WORK_DIR"
}

install_obfuscation_tools() {
    log_info "Installing obfuscation tools..."
    
    export PATH=$PATH:/usr/local/go/bin
    
    if ! command -v garble &>/dev/null; then
        log_info "Installing garble..."
        go install mvdan.cc/garble@latest
    fi

    if ! command -v javascript-obfuscator &>/dev/null; then
        log_info "Installing javascript-obfuscator..."
        if ! command -v npm &>/dev/null; then
             case $RELEASE in
                ubuntu|debian) apt-get install -y npm ;;
                centos|fedora|almalinux|rocky) yum install -y npm ;;
                alpine) apk add npm ;;
            esac
        fi
        npm install -g javascript-obfuscator
    fi
    
    log_success "Obfuscation tools ready"
}

build_whispera() {
    log_info "Installing Whispera server..."
    
    cd "$WORK_DIR"
    export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin:/root/go/bin
    
    local ARCH="amd64"
    [[ $(uname -m) == "aarch64" ]] && ARCH="arm64"

    log_info "Fetching prebuilt server binary from GitHub Release..."
    local DOWNLOAD_URL="https://github.com/nekoskin/whispera/releases/latest/download/whispera-server-linux-${ARCH}.tar.gz"

    if [[ -n "$DOWNLOAD_URL" ]]; then
        log_info "Downloading binary from $DOWNLOAD_URL..."
        if curl -fL --retry 3 --retry-delay 2 -o whispera-server.tar.gz "$DOWNLOAD_URL"; then
            if tar -xzf whispera-server.tar.gz; then
                rm -f whispera-server.tar.gz
                
                if [[ -f "whispera-server" ]]; then
                    chmod +x whispera-server
                    cp whispera-server "$BIN_PATH/whispera"
                    chmod +x "$BIN_PATH/whispera"
                    log_success "Binary installed from GitHub Release"
                    return
                fi
            fi
        fi
        log_warn "Download failed or invalid archive, falling back to build from source..."
    else
        log_warn "No release found or API rate limit exceeded, building from source..."
    fi

    log_info "Building from source..."

    [[ -z "${WHISPERA_DOMAIN:-}" ]] && install_obfuscation_tools
    export CGO_ENABLED=0
    
    rm -f whispera-server
    
    if garble -literals -tiny -seed=random build -trimpath -ldflags "-w -s" -o whispera-server ./app/server 2>/dev/null; then
        log_success "Obfuscated build successful"
    else
        log_info "Garble build failed or not found, using standard Go build..."
        go build -trimpath -ldflags "-w -s" -o whispera-server ./app/server
    fi
    
    if [[ ! -f "whispera-server" ]]; then
        log_err "Build failed!"
        exit 1
    fi
    
    cp whispera-server "$BIN_PATH/whispera"
    chmod +x "$BIN_PATH/whispera"
    
    log_success "Binary installed to $BIN_PATH/whispera"
}

install_nodejs() {
    log_info "Installing Node.js..."
    
    if command -v node &>/dev/null; then
        local NODE_VER=$(node -v)
        if [[ "${NODE_VER}" > "v18" ]]; then
            log_info "Node.js already installed: $NODE_VER"
            return
        fi
    fi

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case $ID in
            ubuntu|debian)
                curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
                apt-get install -y nodejs >/dev/null 2>&1
                ;;
            centos|fedora|almalinux|rocky)
                curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
                yum install -y nodejs >/dev/null 2>&1
                ;;
            alpine)
                apk add nodejs npm >/dev/null 2>&1
                ;;
        esac
    fi
    
    log_success "Node.js installed"
}

cleanup_source() {
    log_info "Cleaning up source code..."
    cd /
    rm -rf "$WORK_DIR"
    if [[ -d "$WORK_DIR" ]]; then
        log_warn "Failed to remove source directory"
    else
        log_success "Source code removed (Security)"
    fi
}

generate_keys() {
    log_info "Generating X25519 keypair..."
    
    mkdir -p "$CONF_PATH"
    
    local OUTPUT=$("$BIN_PATH/whispera" x25519 2>/dev/null)
    local PRIVATE_KEY=$(echo "$OUTPUT" | grep "Private Key:" | awk '{print $3}')
    local PUBLIC_KEY=$(echo "$OUTPUT" | grep "Public Key:" | awk '{print $3}')
    
    if [[ -z "$PRIVATE_KEY" ]]; then
        log_err "Failed to generate keys"
        exit 1
    fi
    
    echo "$PRIVATE_KEY" > "$CONF_PATH/server.key"
    echo "$PUBLIC_KEY" > "$CONF_PATH/server.pub"
    
    log_success "Keys generated"
}

generate_config() {
    log_info "Generating configuration..."
    
    local PRIVATE_KEY=$(cat "$CONF_PATH/server.key" 2>/dev/null)
    
    if [[ -z "$PRIVATE_KEY" ]]; then
        generate_keys
        PRIVATE_KEY=$(cat "$CONF_PATH/server.key")
    fi
    
    local PG_PASS=""
    local PG_URL=""
    if [[ -f "$CONF_PATH/postgres.env" ]]; then
        PG_PASS=$(grep POSTGRES_PASSWORD "$CONF_PATH/postgres.env" | cut -d= -f2)
        if [[ -n "$PG_PASS" ]]; then
            PG_URL="postgresql://whispera:${PG_PASS}@localhost/whispera"
        fi
    fi
    
    local ADMIN_PASS=$(gen_password 30)
    echo "$ADMIN_PASS" > "$CONF_PATH/admin.pass"
    chmod 600 "$CONF_PATH/admin.pass"
    local ADMIN_HASH=$("$BIN_PATH/whispera" hash-password "$ADMIN_PASS" 2>/dev/null || echo "")

    if [[ -n "$PG_PASS" ]]; then
        log_info "Creating admin user in database..."
        if "$BIN_PATH/whispera" create-admin -email "admin" -password "$ADMIN_PASS" -db "postgresql://whispera:$PG_PASS@localhost/whispera" 2>/dev/null; then
            echo "$ADMIN_PASS" > "$CONF_PATH/admin.pass"
            chmod 600 "$CONF_PATH/admin.pass"
        else
            log_warn "Failed to create admin user in database (config.yaml fallback will be used)"
        fi
    else
        log_warn "Skipping admin creation (Postgres not configured)"
    fi

    local DECOY_FIRST_SITE="${WHISPERA_DECOY_SITES%%,*}"
    DECOY_FIRST_SITE="${DECOY_FIRST_SITE:-https://ria.ru/}"
    local DECOY_ORIGIN="${DECOY_FIRST_SITE%%/}"
    log_info "Whispera decoy origin: $DECOY_ORIGIN (fallback target for unauthenticated probes; per-key TLS certs are cloned by 'whispera create-key -sni <domain>')"

    local WHISPERA_PUBLIC_URL=""
    local WHISPERA_DOMAIN_CFG=""
    local WHISPERA_BACKEND_LINE=""
    if [[ -n "${WHISPERA_DOMAIN:-}" ]]; then
        WHISPERA_PUBLIC_URL="https://$WHISPERA_DOMAIN"
        WHISPERA_DOMAIN_CFG="$WHISPERA_DOMAIN"
        WHISPERA_BACKEND_LINE='  backend_h2c_addr: "127.0.0.1:8444"'
        DECOY_ORIGIN="http://127.0.0.1:8081"
        log_info "Domain mode ($WHISPERA_DOMAIN): whispera serves h2c on 127.0.0.1:8444 behind Caddy; keys use SNI/addr $WHISPERA_DOMAIN:443; decoy served locally by Caddy"
    fi

    cat > "$CONF_PATH/config.yaml" <<EOF
server:
  name: whispera-server
  listen_addr: "0.0.0.0:443"
  public_url: "$WHISPERA_PUBLIC_URL"
  private_key: "$PRIVATE_KEY"
  mtu: 1420
  workers: 8

transport:
  udp:
    enabled: false
    listen_addr: ":8443"
  tcp:
    enabled: false
    listen_addr: ":8443"

whispera:
  enabled: true
  listen_addr: ":443"
$WHISPERA_BACKEND_LINE
  tls_cert: ""
  tls_key: ""
  domain: "$WHISPERA_DOMAIN_CFG"
  acme_dir: "/var/lib/whispera/acme"
  decoy_origin: "$DECOY_ORIGIN"

network:
  tun_name: "Whispera"
  tun_ip: "198.18.0.1"
  tun_mtu: 1420
  dns: "1.1.1.1"

relay:
  max_streams: 10000
  enable_tcp: true
  enable_udp: true

session:
  max_sessions: 10000
  idle_timeout: 300
  cleanup_interval: 60

api:
  enabled: true
  listen_addr: "127.0.0.1:8080"
  web_root: ""
  admin_username: "admin"
  admin_password_hash: "$ADMIN_HASH"
  enable_cors: true
  login_rate_limit: 5

bot:
  enabled: false
  token: "YOUR_TELEGRAM_BOT_TOKEN"
  debug: false
  admin_id: 0
  monitor_admin_ids: []

notifications:
  enabled: false
  token: "YOUR_TELEGRAM_BOT_TOKEN"
  chat_id: ""

database:
  postgres_url: "$PG_URL"
  max_conns: 25
  min_conns: 5

ml:
  enabled: false
  server_url: "https://127.0.0.1:8000"
  token_file: ""

EOF
    
    log_success "Config saved to $CONF_PATH/config.yaml"
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
        log_warn "nginx install failed (no outbound? unsupported distro) — whispera decoy backend unavailable until nginx is installed"
        return
    fi

    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/whispera-ratelimit.conf <<'RLCONF'
limit_req_zone $binary_remote_addr zone=panel_auth:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=panel_api:10m  rate=60r/s;
limit_req_status 429;
RLCONF

    setup_decoy_refresh
    /usr/local/bin/whispera-refresh-decoy.sh >/dev/null 2>&1 || true
    if [[ -f /var/www/whispera-decoy/index.html ]]; then
        log_info "Decoy backend populated"
    else
        log_warn "Decoy backend clone failed on first run — will retry on next timer tick"
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

    fw_allow_port 80 tcp
    fw_allow_port 443 tcp

    if nginx -t 2>/dev/null; then
        systemctl enable nginx >/dev/null 2>&1
        systemctl restart nginx
        log_success "Nginx reverse proxy configured"
    else
        log_warn "Nginx config test failed — check /etc/nginx/conf.d/whispera-ui.conf"
    fi
}

setup_caddy_front() {
    [[ -z "${WHISPERA_DOMAIN:-}" ]] && return 0
    log_info "Domain mode: configuring Caddy TLS front for $WHISPERA_DOMAIN"

    local SERVER_IP RESOLVED
    SERVER_IP=$(get_public_ip)
    RESOLVED=$(getent hosts "$WHISPERA_DOMAIN" 2>/dev/null | awk '{print $1}' | head -n1)
    if [[ -n "$RESOLVED" && -n "$SERVER_IP" && "$RESOLVED" != "$SERVER_IP" ]]; then
        log_warn "DNS: $WHISPERA_DOMAIN resolves to $RESOLVED but this server is $SERVER_IP — Caddy cert issuance will fail until the A-record points here"
    elif [[ -z "$RESOLVED" ]]; then
        log_warn "DNS: $WHISPERA_DOMAIN does not resolve yet — set the A-record to $SERVER_IP or Caddy cannot obtain a certificate"
    fi

    if ! command -v caddy &>/dev/null; then
        log_info "Installing Caddy..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg >/dev/null 2>&1
            curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
            curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null 2>&1
            apt-get update >/dev/null 2>&1 && apt-get install -y caddy >/dev/null 2>&1
        elif command -v dnf &>/dev/null; then
            dnf install -y 'dnf-command(copr)' >/dev/null 2>&1
            dnf copr enable -y @caddy/caddy >/dev/null 2>&1
            dnf install -y caddy >/dev/null 2>&1
        else
            log_warn "Auto-install of Caddy unsupported on this distro — install caddy manually, then re-run"
            return 1
        fi
    fi
    if ! command -v caddy &>/dev/null; then
        log_warn "Caddy install failed — domain mode NOT active; whispera h2c backend on 127.0.0.1:8444 has no public TLS front"
        return 1
    fi

    mkdir -p /var/www/whispera-decoy
    setup_decoy_refresh
    /usr/local/bin/whispera-refresh-decoy.sh >/dev/null 2>&1 || true

    mkdir -p /etc/caddy
    cat > /etc/caddy/Caddyfile <<CADDY
{
    auto_https disable_redirects
}

$WHISPERA_DOMAIN {
    reverse_proxy 127.0.0.1:8444 {
        transport http {
            versions h2c
        }
    }
}

http://127.0.0.1:8081 {
    root * /var/www/whispera-decoy
    file_server
}
CADDY

    fw_allow_port 443 tcp
    systemctl enable caddy >/dev/null 2>&1
    if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
        systemctl restart caddy
        log_success "Caddy front configured for $WHISPERA_DOMAIN (auto-TLS via Let's Encrypt, TLS-ALPN-01 on 443)"
        log_info "Issue client keys with SNI/addr = $WHISPERA_DOMAIN, e.g.: whispera create-key -sni $WHISPERA_DOMAIN"
    else
        log_warn "Caddyfile validation failed — check /etc/caddy/Caddyfile"
    fi
}

setup_systemd() {
    log_info "Setting up SystemD services..."

    make_service_user whispera
    ensure_integrity_key

    if command -v ufw &>/dev/null; then
        local UFW_BIN
        UFW_BIN=$(command -v ufw)
        echo "whispera ALL=(ALL) NOPASSWD: $UFW_BIN" > /etc/sudoers.d/whispera-ufw
        chmod 440 /etc/sudoers.d/whispera-ufw
        log_info "Configured sudo access for UFW"
    fi

    mkdir -p "$LOG_PATH"
    mkdir -p "$DAT_PATH/panel/public/uploads"
    mkdir -p /var/lib/whispera/acme
    chown -R whispera:whispera "$WORK_DIR" "$CONF_PATH" "$DAT_PATH" "$LOG_PATH" /var/lib/whispera 2>/dev/null || true
    chmod 750 "$CONF_PATH"
    chmod 640 "$CONF_PATH/config.yaml" 2>/dev/null || true

    if ! has_systemd; then
        log_warn "No systemd detected (Alpine/OpenRC?). User & config are set up, but service units were NOT installed."
        log_warn "Start manually: $BIN_PATH/whispera -config $CONF_PATH/config.yaml -api 127.0.0.1:8080"
        return 0
    fi

    cat > /etc/systemd/system/whispera.service <<EOF
[Unit]
Description=Whispera Server (Backend)
Documentation=https://github.com/nekoskin/whispera
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
User=whispera
Group=whispera
WorkingDirectory=$WORK_DIR
Environment=WHISPERA_MASK_LOGS=true
EnvironmentFile=-$INTEGRITY_ENV_FILE
ExecStart=$BIN_PATH/whispera -config $CONF_PATH/config.yaml -api 127.0.0.1:8080
Restart=always
RestartSec=5
LimitNOFILE=infinity
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$WORK_DIR $CONF_PATH $DAT_PATH /var/log/whispera /run -/etc/ufw -/lib/ufw -/var/lib/ufw -/var/crash
StandardOutput=append:/var/log/whispera/whispera.log
StandardError=append:/var/log/whispera/whispera.log

[Install]
WantedBy=multi-user.target
EOF

    log_info "ML engine is built into the main Whispera binary (no Python required)"
    _enable_ml_in_config

    systemctl daemon-reload
    systemctl enable whispera >/dev/null 2>&1

    cat > /etc/systemd/system/whispera-watchdog.service <<WEOF
[Unit]
Description=Whispera Watchdog
After=whispera.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for svc in whispera; do systemctl is-enabled \$svc &>/dev/null && ! systemctl is-active \$svc &>/dev/null && systemctl restart \$svc && echo "[\$(date)] restarted \$svc" >> /var/log/whispera/watchdog.log; done'
WEOF

    cat > /etc/systemd/system/whispera-watchdog.timer <<WEOF
[Unit]
Description=Whispera Watchdog Timer

[Timer]
OnBootSec=60
OnUnitActiveSec=120

[Install]
WantedBy=timers.target
WEOF

    systemctl enable whispera-watchdog.timer >/dev/null 2>&1
    systemctl start whispera-watchdog.timer >/dev/null 2>&1

    systemctl daemon-reload

    if systemctl restart whispera 2>/dev/null; then
        log_success "Whispera service started"
    else
        log_warn "Whispera service failed to start — check /var/log/whispera/whispera.log"
    fi

    log_success "Panel served as static files via nginx"

    log_success "ML engine runs inside main Whispera process (port 8000)"
}

setup_network() {
    log_info "Configuring network..."
    
    if ! command -v iptables &>/dev/null; then
        log_info "Installing iptables..."
        apt-get update >/dev/null 2>&1
        apt-get install -y iptables >/dev/null 2>&1 || yum install -y iptables >/dev/null 2>&1
    fi
    
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    
    if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi
    
    local WAN_IF=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -n "$WAN_IF" ]] && command -v iptables &>/dev/null; then
        iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
        iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
    fi
    
    log_success "Network configured"
}

setup_firewall() {
    log_info "Configuring firewall..."

    if command -v ufw &>/dev/null; then
        ufw default deny incoming >/dev/null 2>&1 || true
        ufw default allow outgoing >/dev/null 2>&1 || true

        ufw allow ssh >/dev/null 2>&1 || true
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true

        ufw --force enable >/dev/null 2>&1 || true
        log_success "UFW configured (default deny incoming; 22/80/443 only — admin API stays on 127.0.0.1)"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        log_success "Firewalld configured"
    elif command -v iptables &>/dev/null; then
        for p in 22 80 443; do
            iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || true
        done
        log_success "iptables rules added (not persistent without netfilter-persistent)"
    else
        log_warn "No firewall found, skipping"
    fi
}

install_cli_wrapper() {
    cat > "$BIN_PATH/whispera-mgmt" <<'EOF'
case $1 in
    start) systemctl start whispera ;;
    stop) systemctl stop whispera ;;
    restart) systemctl restart whispera ;;
    status) systemctl status whispera ;;
    log|logs) journalctl -u whispera -f ;;
    config) ${EDITOR:-nano} /etc/whispera/config.yaml ;;
    key)
        SERVER_IP=$(curl -s https://2ip.ru/api/self -m 5 2>/dev/null | grep -oE '"ip":"[^"]*"' | cut -d'"' -f4 || curl -s https://api.ipify.org -m 5 2>/dev/null || echo "YOUR_IP")
        ADMIN_PASS=$(cat /etc/whispera/admin.pass 2>/dev/null)
        echo "Web Panel:    https://${SERVER_IP}/"
        echo "Admin User:   admin"
        echo "Admin Pass:   ${ADMIN_PASS}"
        ;;
    update)
        bash /opt/whispera/update.sh
        ;;
    menu|extras)
        bash /opt/whispera/update.sh extras
        ;;
    *) echo "Usage: whispera-mgmt {start|stop|restart|status|log|config|key|update|menu}" ;;
esac
EOF
    chmod +x "$BIN_PATH/whispera-mgmt"
    
    cat > "$BIN_PATH/menu" <<EOF
bash /opt/whispera/update.sh extras
EOF
    chmod +x "$BIN_PATH/menu"
    
    cat > "$WORK_DIR/menu" <<EOF
bash /opt/whispera/update.sh extras
EOF
    chmod +x "$WORK_DIR/menu"
    
    log_success "CLI wrapper installed (whispera-mgmt, menu)"
}

install_relay() {
    check_root
    check_os
    print_logo

    log_info "Installing Whispera relay (minimal, no panel/DB)..."

    install_dependencies
    install_go
    clone_or_update_repo
    build_whispera

    mkdir -p "$CONF_PATH"

    local RELAY_SECRET
    RELAY_SECRET=$("$BIN_PATH/whispera" keygen 2>/dev/null)
    if [[ -z "$RELAY_SECRET" ]]; then
        RELAY_SECRET=$(openssl rand -base64 32 2>/dev/null | tr -d '\n')
    fi

    local CERT="$CONF_PATH/relay.crt"
    local KEY="$CONF_PATH/relay.key"
    if [[ ! -f "$CERT" ]]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$KEY" -out "$CERT" \
            -days 3650 -subj "/CN=relay" 2>/dev/null
        chmod 600 "$KEY"
    fi

    if [[ ! -f "$CONF_PATH/config.yaml" ]]; then
        cat > "$CONF_PATH/config.yaml" <<EOF
server:
  name: whispera-relay
  listen_addr: "0.0.0.0:8443"
  private_key: ""
  mtu: 1420
  workers: 4

transport:
  udp:
    enabled: false
  tcp:
    enabled: true
    buffer_size: 65536

relay:
  max_streams: 50000
  enable_tcp: true
  enable_udp: false

session:
  max_sessions: 50000
  idle_timeout: 300
  cleanup_interval: 60

api:
  enabled: true
  listen_addr: "127.0.0.1:8080"

whispera:
  enabled: true
  listen_addr: ":443"
  tls_cert: "$CERT"
  tls_key: "$KEY"
  secret: "$RELAY_SECRET"
EOF
        refresh_config
        log_success "Relay config saved to $CONF_PATH/config.yaml"
    else
        if ! grep -q "^  secret:" "$CONF_PATH/config.yaml"; then
            sed -i "/^whispera:/a\\  secret: \"$RELAY_SECRET\"" "$CONF_PATH/config.yaml"
            refresh_config
        else
            RELAY_SECRET=$(grep "^  secret:" "$CONF_PATH/config.yaml" | awk '{print $2}' | tr -d '"')
            log_info "Relay config already exists, using existing secret"
        fi
    fi

    make_service_user whispera
    ensure_integrity_key

    if has_systemd; then
        cat > /etc/systemd/system/whispera.service <<EOF
[Unit]
Description=Whispera Relay
After=network.target network-online.target
Wants=network-online.target

[Service]
User=whispera
Group=whispera
WorkingDirectory=$WORK_DIR
EnvironmentFile=-$INTEGRITY_ENV_FILE
ExecStart=$BIN_PATH/whispera -config $CONF_PATH/config.yaml -api 127.0.0.1:8080
Restart=always
RestartSec=5
LimitNOFILE=infinity
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$WORK_DIR $CONF_PATH $DAT_PATH /var/log/whispera /run

[Install]
WantedBy=multi-user.target
EOF
        chown -R whispera:whispera "$CONF_PATH" 2>/dev/null || true
        systemctl daemon-reload
        systemctl enable whispera >/dev/null 2>&1
        systemctl restart whispera
        log_success "Relay service started"
    fi

    if command -v ufw &>/dev/null; then
        ufw allow ssh >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
        ufw --force enable >/dev/null 2>&1 || true
    fi

    install_cli_wrapper

    echo ""
    log_success "Whispera relay installed!"
    echo ""
    echo -e "  ${YELLOW}Whispera secret (скопируй на мастер):${PLAIN}"
    echo -e "  ${GREEN}${RELAY_SECRET}${PLAIN}"
    echo ""
    echo -e "  Используй в конфиге мастера:"
    echo -e "  ${GREEN}whispera_secret: \"${RELAY_SECRET}\"${PLAIN}"
    echo ""
}

main() {
    check_root
    check_os
    print_logo
    
    install_dependencies
    install_go
    clone_or_update_repo
    build_whispera
    [[ -z "${WHISPERA_DOMAIN:-}" ]] && install_panel

    if [[ ! -f "$CONF_PATH/config.yaml" ]]; then
        generate_keys
        generate_config
    else
        log_info "Config exists, keeping current configuration"
    fi
    
    install_cli_wrapper
    setup_network
    setup_firewall
    setup_systemd
    [[ -z "${WHISPERA_DOMAIN:-}" ]] && setup_nginx_proxy
    setup_caddy_front

    _enable_whispera_in_config
    refresh_config
    if systemctl is-active whispera &>/dev/null; then
        systemctl restart whispera >/dev/null 2>&1 || true
    fi

    local PG_PASS=""
    local ADMIN_PASS=""
    
    if [[ -f "$CONF_PATH/postgres.env" ]]; then
        PG_PASS=$(grep POSTGRES_PASSWORD "$CONF_PATH/postgres.env" | cut -d= -f2)
    fi
    if [[ -f "$CONF_PATH/admin.pass" ]]; then
        ADMIN_PASS=$(cat "$CONF_PATH/admin.pass")
    fi

    echo ""
    log_success "Whispera installed successfully!"
    echo ""
    echo -e "  Manage:         ${GREEN}whispera-mgmt${PLAIN}"
    echo -e "  Config:         ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
    local SERVER_IP
    SERVER_IP=$(get_public_ip)
    echo -e "  ${YELLOW}(self sert)${PLAIN}"
    echo ""
    echo -e "  ${YELLOW}Admin User:${PLAIN}     admin"
    echo -e "  ${YELLOW}Admin Password:${PLAIN} ${GREEN}$ADMIN_PASS${PLAIN}"
    echo ""
    echo -e "  ${YELLOW}DB Password:${PLAIN}    $PG_PASS"

    setup_dns_discovery
    
    show_extras_menu
}


case "${1:-}" in
    relay)
        install_relay
        ;;
    keygen)
        generate_keys
        generate_config
        systemctl restart whispera 2>/dev/null || true
        SERVER_IP=$(get_public_ip)
        ADMIN_PASS=$(cat "$CONF_PATH/admin.pass" 2>/dev/null)
        log_success "Keys regenerated. Panel: https://${SERVER_IP}/ (admin / ${ADMIN_PASS})"
        ;;
    update)
        log_info "Updating Whispera..."
        clone_or_update_repo
        build_whispera
        
        if ! grep -q "^  private_key:" "$CONF_PATH/config.yaml"; then
             log_info "Migrating config: ensuring private_key is in server section..."
             EXISTING_KEY=$(grep "private_key:" "$CONF_PATH/config.yaml" | head -n 1 | awk '{print $2}' | tr -d '"')
             [[ -z "$EXISTING_KEY" ]] && EXISTING_KEY=$(cat "$CONF_PATH/server.key" 2>/dev/null)
             
             if [[ -n "$EXISTING_KEY" ]]; then
                 sed -i "/listen_addr: \"0.0.0.0:8443\"/a \  private_key: \"$EXISTING_KEY\"" "$CONF_PATH/config.yaml"
                 log_success "Config successfully migrated"
             fi
        fi

        systemctl restart whispera
        log_success "Update complete"
        ;;
    bbr)
        check_root
        setup_bbr
        ;;
    warp)
        check_root
        check_os
        setup_warp
        ;;
    fail2ban)
        check_root
        check_os
        setup_fail2ban
        ;;
    swap)
        check_root
        setup_swap
        ;;
    optimize)
        check_root
        setup_sysctl
        ;;
    autoupdate)
        check_root
        setup_autoupdate
        ;;
    harden)
        check_root
        setup_ssh_hardening
        ;;
    telegram)
        check_root
        setup_telegram
        ;;
    extras)
        check_root
        check_os
        show_extras_menu
        ;;
    restart)
        systemctl restart whispera
        log_success "Whispera restarted"
        ;;
    status)
        systemctl status whispera
        ;;
    help|--help|-h)
        echo "Whispera"
        echo ""
        echo "Usage: ./install.sh [command]"
        echo ""
        echo "Commands:"
        echo "  (no args)   Full installation + extras menu"
        echo "  keygen      Regenerate keys"
        echo "  key         Show connection key"
        echo "  update      Pull latest and rebuild"
        echo "  extras      Show extras menu"
        echo ""
        echo "Individual extras:"
        echo "  bbr         Enable BBR (faster TCP)"
        echo "  warp        Cloudflare WARP (hide IP)"
        echo "  fail2ban    Protect SSH from brute-force"
        echo "  swap        Create 2GB swap"
        echo "  optimize    Tune sysctl settings"
        echo "  autoupdate  Enable daily auto-updates"
        echo "  harden      SSH hardening (keys only)"
        echo ""
        echo "Service:"
        echo "  restart     Restart Whispera"
        echo "  status      Show status"
        echo ""
        echo "One-liner install:"
        echo "  bash <(curl -sL https://raw.githubusercontent.com/nekoskin/whispera/main/install.sh)"
        ;;
    *)
        main "$@"
        ;;
esac
