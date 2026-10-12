#!/usr/bin/env bash
# Install the newest trojan-rs x86_64 musl release with built-in ACME TLS.

set -Eeuo pipefail
IFS=$'\n\t'

readonly REPOSITORY='willoong9559/trojan-rs'
readonly RELEASE_API="https://api.github.com/repos/${REPOSITORY}/releases/latest"
readonly RELEASE_ASSET='rust-build-x86_64-unknown-linux-musl.zip'
readonly TROJAN_USER='trojan-rs'
readonly TROJAN_CONFIG='/etc/trojan-rs/server.toml'
readonly TROJAN_BINARY='/usr/local/bin/trojan-rs'

DOMAIN=''
EMAIL=''
SERVICE_NAME='GunService'
PASSWORD=''
ACME_CACHE_DIR='/var/lib/trojan-rs/acme'
ACME_STAGING=0
TEMP_DIR=''

usage() {
    cat <<'EOF'
Usage:
  sudo ./scripts/install_acme_grpc.sh --domain example.com --email admin@example.com [options]

Options:
  --service-name NAME  gRPC service name (default: GunService)
  --password VALUE     Trojan password; prefer omitting this to be prompted securely
  --acme-cache-dir DIR Directory for ACME account and certificate state
  --acme-staging       Use the Let's Encrypt staging environment
  -h, --help           Show this help

The domain must resolve to this host and TCP port 443 must be available for
Trojan-RS. Certificate issuance and renewal use TLS-ALPN-01 on port 443.
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
        --acme-cache-dir)
            ACME_CACHE_DIR=${2:?missing value for --acme-cache-dir}
            shift 2
            ;;
        --acme-staging)
            ACME_STAGING=1
            shift
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

[[ $EUID -eq 0 ]] || die 'run this script as root (for example: sudo bash scripts/install_acme_grpc.sh ...)'
[[ -n "$DOMAIN" ]] || die '--domain is required'
[[ -n "$EMAIL" ]] || die '--email is required'
[[ $(uname -m) == 'x86_64' ]] || die 'the selected release asset supports x86_64 Linux only'
[[ $DOMAIN =~ ^[A-Za-z0-9.-]+$ && $DOMAIN != .* && $DOMAIN != *..* ]] || die 'invalid domain name'
[[ $EMAIL == *@* ]] || die 'invalid email address'
[[ $SERVICE_NAME =~ ^[A-Za-z0-9._-]+$ ]] || die 'service name may contain only letters, numbers, dot, underscore, and hyphen'
[[ $ACME_CACHE_DIR == /* ]] || die '--acme-cache-dir must be absolute'
[[ -d /run/systemd/system ]] || die 'this script requires systemd'

if [[ -z "$PASSWORD" ]]; then
    read -r -s -p 'Trojan password: ' PASSWORD
    echo
    [[ -n "$PASSWORD" ]] || die 'password must not be empty'
fi

install_packages() {
    local -a packages=(curl unzip jq ca-certificates)

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
        die 'unsupported package manager; install curl, unzip, jq, and ca-certificates manually'
    fi
}

install_packages
for command in curl unzip jq systemctl; do
    command -v "$command" >/dev/null || die "required command is unavailable: $command"
done

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

install -d -o "$TROJAN_USER" -g "$TROJAN_USER" -m 0700 /etc/trojan-rs "$ACME_CACHE_DIR"
cat >"$TEMP_DIR/server.toml" <<EOF
[server]
host = "0.0.0.0"
port = "443"
password = "${PASSWORD_TOML}"
enable_udp = true
enable_ws = false
enable_grpc = true
grpc_service_name = "${SERVICE_NAME}"
acme_domain = "${DOMAIN}"
acme_email = "${EMAIL}"
acme_cache_dir = "${ACME_CACHE_DIR}"
acme_staging = $([[ $ACME_STAGING -eq 1 ]] && echo true || echo false)

[log]
level = "info"
EOF
install -o "$TROJAN_USER" -g "$TROJAN_USER" -m 0600 "$TEMP_DIR/server.toml" "$TROJAN_CONFIG"

cat >"$TEMP_DIR/trojan-rs.service" <<EOF
[Unit]
Description=trojan-rs with automatic ACME TLS certificates
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${TROJAN_USER}
Group=${TROJAN_USER}
UMask=0077
StateDirectory=trojan-rs
StateDirectoryMode=0700
ExecStart=${TROJAN_BINARY} --config-file ${TROJAN_CONFIG}
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
install -m 0644 "$TEMP_DIR/trojan-rs.service" /etc/systemd/system/trojan-rs.service
systemctl daemon-reload
systemctl enable trojan-rs
systemctl restart trojan-rs
systemctl --no-pager --full status trojan-rs

echo
echo 'Deployment complete.'
echo "gRPC path: /${SERVICE_NAME}/Tun"
echo "ACME domain: ${DOMAIN}"
echo "Installed release: ${RELEASE_TAG}"
