#!/usr/bin/env bash
# Deploy the newest trojan-rs x86_64 musl release behind Nginx gRPC over UDS.

set -Eeuo pipefail
IFS=$'\n\t'

readonly REPOSITORY='willoong9559/trojan-rs'
readonly RELEASE_API="https://api.github.com/repos/${REPOSITORY}/releases/latest"
readonly RELEASE_ASSET='rust-build-x86_64-unknown-linux-musl.zip'

DOMAIN=''
EMAIL=''
SERVICE_NAME='GunService'
PASSWORD=''
NGINX_USER=''
NGINX_CONF='/etc/nginx/conf.d/trojan-rs.conf'
ACME_WEBROOT='/var/www/acme-challenge'
SOCKET_PATH='/run/trojan-rs/trojan-rs.sock'

readonly TROJAN_USER='trojan-rs'
readonly TROJAN_CONFIG='/etc/trojan-rs/server.toml'
readonly TROJAN_BINARY='/usr/local/bin/trojan-rs'

TEMP_DIR=''
NGINX_BACKUP=''
NGINX_CONFIG_EXISTED=0

usage() {
    cat <<'EOF'
Usage:
  sudo ./scripts/install_nginx_grpc.sh --domain example.com --email admin@example.com [options]

Options:
  --service-name NAME   gRPC service name (default: GunService)
  --password VALUE      Trojan password; prefer omitting this to be prompted securely
  --nginx-user USER     Nginx worker user; autodetected from nginx.conf when omitted
  --nginx-conf PATH     Managed Nginx virtual-host path
  --webroot PATH        ACME HTTP-01 webroot
  --socket-path PATH    UDS path for trojan-rs and Nginx
  -h, --help            Show this help

The script requires a public DNS A/AAAA record for --domain pointing at this
host and inbound TCP ports 80 and 443. Re-running it downloads the latest
GitHub release and safely replaces the files it manages.
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] && rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

restore_nginx_config() {
    if (( NGINX_CONFIG_EXISTED )); then
        install -D -m 0644 "$NGINX_BACKUP" "$NGINX_CONF"
    else
        rm -f -- "$NGINX_CONF"
    fi
}

while (($#)); do
    case "$1" in
        --domain)
            DOMAIN=${2:?missing value for --domain}
            shift 2
            ;;
        --email)
            EMAIL=${2:?missing value for --email}
            shift 2
            ;;
        --service-name)
            SERVICE_NAME=${2:?missing value for --service-name}
            shift 2
            ;;
        --password)
            PASSWORD=${2:?missing value for --password}
            shift 2
            ;;
        --nginx-user)
            NGINX_USER=${2:?missing value for --nginx-user}
            shift 2
            ;;
        --nginx-conf)
            NGINX_CONF=${2:?missing value for --nginx-conf}
            shift 2
            ;;
        --webroot)
            ACME_WEBROOT=${2:?missing value for --webroot}
            shift 2
            ;;
        --socket-path)
            SOCKET_PATH=${2:?missing value for --socket-path}
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

[[ $EUID -eq 0 ]] || die 'run this script as root (for example: sudo bash scripts/install_nginx_grpc.sh ...)'
[[ -n "$DOMAIN" ]] || die '--domain is required'
[[ -n "$EMAIL" ]] || die '--email is required'
[[ $(uname -m) == 'x86_64' ]] || die 'the selected release asset supports x86_64 Linux only'
[[ $DOMAIN =~ ^[A-Za-z0-9.-]+$ && $DOMAIN != .* && $DOMAIN != *..* ]] || die 'invalid domain name'
[[ $SERVICE_NAME =~ ^[A-Za-z0-9._-]+$ ]] || die 'service name may contain only letters, numbers, dot, underscore, and hyphen'
[[ $SOCKET_PATH == /* ]] || die '--socket-path must be absolute'
[[ -d /run/systemd/system ]] || die 'this script requires systemd'

if [[ -z "$PASSWORD" ]]; then
    read -r -s -p 'Trojan password: ' PASSWORD
    echo
    [[ -n "$PASSWORD" ]] || die 'password must not be empty'
fi

install_packages() {
    local -a packages=(nginx curl unzip jq ca-certificates)

    if command -v apt-get >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y "${packages[@]}"
    elif command -v dnf >/dev/null; then
        dnf install -y "${packages[@]}"
    elif command -v yum >/dev/null; then
        yum install -y "${packages[@]}"
    elif command -v zypper >/dev/null; then
        zypper --non-interactive install --no-recommends "${packages[@]}"
    elif command -v pacman >/dev/null; then
        pacman --sync --refresh --noconfirm "${packages[@]}"
    else
        die 'unsupported package manager; install nginx, curl, unzip, jq, and ca-certificates manually'
    fi
}

install_packages

for command in nginx curl unzip jq systemctl; do
    command -v "$command" >/dev/null || die "required command is unavailable: $command"
done

if [[ -z "$NGINX_USER" ]]; then
    NGINX_USER=$(sed -nE 's/^[[:space:]]*user[[:space:]]+([^[:space:];]+).*/\1/p' /etc/nginx/nginx.conf | head -n 1 || true)
fi
if [[ -z "$NGINX_USER" ]]; then
    if id nginx >/dev/null 2>&1; then
        NGINX_USER='nginx'
    elif id www-data >/dev/null 2>&1; then
        NGINX_USER='www-data'
    else
        die 'could not determine the Nginx worker user; pass --nginx-user explicitly'
    fi
fi
id "$NGINX_USER" >/dev/null 2>&1 || die "Nginx user does not exist: $NGINX_USER"
NGINX_GROUP=$(id -gn "$NGINX_USER")

if ! id "$TROJAN_USER" >/dev/null 2>&1; then
    if command -v useradd >/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$TROJAN_USER"
    elif command -v adduser >/dev/null; then
        adduser -S -D -H -s /sbin/nologin "$TROJAN_USER"
    else
        die 'could not create the trojan-rs service user'
    fi
fi

TEMP_DIR=$(mktemp -d)
mkdir -p "$ACME_WEBROOT" "$(dirname "$NGINX_CONF")" /etc/trojan-rs
chmod 0755 "$ACME_WEBROOT"

if [[ -f "$NGINX_CONF" ]]; then
    NGINX_CONFIG_EXISTED=1
    NGINX_BACKUP="$TEMP_DIR/nginx.conf.backup"
    cp -a "$NGINX_CONF" "$NGINX_BACKUP"
fi

write_http_nginx_config() {
    cat >"$TEMP_DIR/trojan-rs.http.conf" <<EOF
# Managed by install_nginx_grpc.sh.
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root ${ACME_WEBROOT};
        default_type text/plain;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF
}

write_full_nginx_config() {
    local cert_dir="/etc/nginx/ssl/${DOMAIN}"
    cat >"$TEMP_DIR/trojan-rs.full.conf" <<EOF
# Managed by install_nginx_grpc.sh.
upstream trojan_rs_grpc {
    least_conn;
    keepalive 128;
    server unix:${SOCKET_PATH};
}

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location ^~ /.well-known/acme-challenge/ {
        root ${ACME_WEBROOT};
        default_type text/plain;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    location = /${SERVICE_NAME}/Tun {
        grpc_pass grpc://trojan_rs_grpc;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        client_max_body_size 0;
        client_body_timeout 1d;
        grpc_connect_timeout 10s;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_socket_keepalive on;
    }

    location / {
        return 404;
    }
}
EOF
}

install_nginx_config() {
    local source=$1
    install -m 0644 "$source" "$NGINX_CONF"
    if ! nginx -t; then
        restore_nginx_config
        nginx -t || true
        die 'generated Nginx configuration is invalid; the previous managed file was restored'
    fi
    systemctl reload nginx
}

systemctl enable --now nginx
write_http_nginx_config
install_nginx_config "$TEMP_DIR/trojan-rs.http.conf"

ACME_SH=/root/.acme.sh/acme.sh
if [[ ! -x "$ACME_SH" ]]; then
    curl -fsSL https://get.acme.sh | sh -s email="$EMAIL"
fi
[[ -x "$ACME_SH" ]] || die 'acme.sh installation failed'

"$ACME_SH" --set-default-ca --server letsencrypt
"$ACME_SH" --issue --server letsencrypt --webroot "$ACME_WEBROOT" --domain "$DOMAIN" --keylength ec-256

CERT_DIR="/etc/nginx/ssl/${DOMAIN}"
install -d -m 0750 "$CERT_DIR"
"$ACME_SH" --install-cert --ecc --domain "$DOMAIN" \
    --fullchain-file "$CERT_DIR/fullchain.pem" \
    --key-file "$CERT_DIR/key.pem" \
    --reloadcmd 'systemctl reload nginx'
chmod 0644 "$CERT_DIR/fullchain.pem"
chmod 0640 "$CERT_DIR/key.pem"

RELEASE_JSON="$TEMP_DIR/release.json"
curl --fail --location --silent --show-error \
    --header 'Accept: application/vnd.github+json' \
    "$RELEASE_API" >"$RELEASE_JSON"
RELEASE_TAG=$(jq -er '.tag_name' "$RELEASE_JSON")
ASSET_URL=$(jq -er --arg name "$RELEASE_ASSET" '.assets[] | select(.name == $name) | .browser_download_url' "$RELEASE_JSON")

echo "Installing trojan-rs ${RELEASE_TAG} from the latest GitHub release"
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
    "$ASSET_URL" --output "$TEMP_DIR/trojan-rs.zip"
unzip -q "$TEMP_DIR/trojan-rs.zip" -d "$TEMP_DIR/release"
RELEASE_BINARY=$(find "$TEMP_DIR/release" -type f -name trojan-rs -print -quit)
[[ -n "$RELEASE_BINARY" ]] || die "${RELEASE_ASSET} does not contain a binary named trojan-rs"
install -D -m 0755 "$RELEASE_BINARY" "$TROJAN_BINARY"

toml_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'
}
PASSWORD_TOML=$(toml_escape "$PASSWORD")

cat >"$TEMP_DIR/server.toml" <<EOF
[server]
# host and port are parser-required placeholders. unix_path selects the listener.
host = "127.0.0.1"
port = "35537"
password = "${PASSWORD_TOML}"
enable_udp = true
enable_ws = false
enable_grpc = true
grpc_service_name = "${SERVICE_NAME}"
unix_path = "${SOCKET_PATH}"

[log]
level = "warn"
EOF
install -o "$TROJAN_USER" -g "$NGINX_GROUP" -m 0600 "$TEMP_DIR/server.toml" "$TROJAN_CONFIG"

cat >"$TEMP_DIR/trojan-rs.service" <<EOF
[Unit]
Description=trojan-rs gRPC backend
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${TROJAN_USER}
Group=${NGINX_GROUP}
UMask=0007
RuntimeDirectory=trojan-rs
RuntimeDirectoryMode=0750
ExecStart=${TROJAN_BINARY} --config-file ${TROJAN_CONFIG}
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
install -m 0644 "$TEMP_DIR/trojan-rs.service" /etc/systemd/system/trojan-rs.service
systemctl daemon-reload
systemctl enable --now trojan-rs
systemctl restart trojan-rs
systemctl --no-pager --full status trojan-rs

write_full_nginx_config
install_nginx_config "$TEMP_DIR/trojan-rs.full.conf"

echo
echo 'Deployment complete.'
echo "gRPC path: /${SERVICE_NAME}/Tun"
echo "Trojan UDS: ${SOCKET_PATH}"
echo "Installed release: ${RELEASE_TAG}"
