#!/usr/bin/env bash
# Set up mailcow-mcp next to an existing mailcow installation.
#
# Read-only by default: it inspects mailcow and prints what it would write. With --apply it writes
# .env, app.env and broker.env here and the nginx site file into mailcow's data/conf/nginx/.
# It never changes mailcow.conf or mailcow's compose files, and never overwrites existing keys.
#
# Usage: ./setup-mailcow.sh --hostname mcp.example.com [--mailcow-dir /opt/mailcow-dockerized]
#            [--oauth-client-id ID --oauth-client-secret SECRET] [--api-key KEY]
#            [--version TAG] [--apply]
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAILCOW_DIR="/opt/mailcow-dockerized"
MCP_HOSTNAME=""
OAUTH_CLIENT_ID=""
OAUTH_CLIENT_SECRET=""
API_KEY=""
MCP_VERSION="latest"
APPLY=0
IMAGE="ghcr.io/nitramxx/mailcow-mcp"

usage() {
    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --hostname) MCP_HOSTNAME="${2:-}"; shift 2 ;;
        --mailcow-dir) MAILCOW_DIR="${2:-}"; shift 2 ;;
        --oauth-client-id) OAUTH_CLIENT_ID="${2:-}"; shift 2 ;;
        --oauth-client-secret) OAUTH_CLIENT_SECRET="${2:-}"; shift 2 ;;
        --api-key) API_KEY="${2:-}"; shift 2 ;;
        --version) MCP_VERSION="${2:-}"; shift 2 ;;
        --apply) APPLY=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 2 ;;
    esac
done

die() { echo "error: $*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

[ -n "$MCP_HOSTNAME" ] || die "--hostname is required (the MCP server's own name, e.g. mcp.example.com)"
[[ "$MCP_HOSTNAME" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] \
    || die "--hostname '$MCP_HOSTNAME' is not a valid hostname"
[ -f "$MAILCOW_DIR/mailcow.conf" ] || die "no mailcow.conf in $MAILCOW_DIR (use --mailcow-dir)"
command -v docker >/dev/null || die "docker is not installed"

# --- read mailcow.conf (without sourcing it) ---------------------------------
conf() {
    local value
    value="$(grep -E "^$1=" "$MAILCOW_DIR/mailcow.conf" | tail -n 1 | cut -d= -f2- || true)"
    value="${value%\"}"; value="${value#\"}"
    printf '%s' "${value:-${2:-}}"
}

MAILCOW_HOSTNAME="$(conf MAILCOW_HOSTNAME)"
[ -n "$MAILCOW_HOSTNAME" ] || die "MAILCOW_HOSTNAME is not set in mailcow.conf"
PROJECT="$(conf COMPOSE_PROJECT_NAME mailcowdockerized)"
IPV4_NETWORK="$(conf IPV4_NETWORK 172.22.1)"
HTTPS_PORT="$(conf HTTPS_PORT 443)"
ENABLE_IPV6="$(conf ENABLE_IPV6 true)"
ADDITIONAL_SAN="$(conf ADDITIONAL_SAN)"
NETWORK="${PROJECT}_mailcow-network"

VERSION="$(git -C "$MAILCOW_DIR" describe --tags 2>/dev/null || true)"
if [ -z "$VERSION" ] && [ -f "$MAILCOW_DIR/data/web/inc/app_info.inc.php" ]; then
    VERSION="$(grep -oE "MAILCOW_GIT_VERSION *= *['\"][^'\"]+" "$MAILCOW_DIR/data/web/inc/app_info.inc.php" | sed -E "s/.*['\"]//" || true)"
fi

echo "mailcow"
note "directory:      $MAILCOW_DIR"
note "version:        ${VERSION:-unknown}"
note "hostname:       $MAILCOW_HOSTNAME"
note "compose project $PROJECT, network $NETWORK ($IPV4_NETWORK.0/24)"

docker network inspect "$NETWORK" >/dev/null 2>&1 \
    || die "docker network $NETWORK not found: is mailcow running?"

# --- addresses -----------------------------------------------------------------
existing() { [ -f "$KIT_DIR/.env" ] && grep -E "^$1=" "$KIT_DIR/.env" | cut -d= -f2- || true; }
used_ips="$(docker network inspect "$NETWORK" -f '{{range .Containers}}{{.IPv4Address}} {{end}}' | tr ' ' '\n' | cut -d/ -f1)"
pick_ip() {
    local skip="$1" n candidate
    for n in $(seq 231 247); do  # mailcow's fixed addresses are .248 and up
        candidate="$IPV4_NETWORK.$n"
        if ! grep -qx "$candidate" <<<"$used_ips" && [ "$candidate" != "$skip" ]; then
            echo "$candidate"; return
        fi
    done
    die "no free address in $IPV4_NETWORK.231-247"
}
APP_IP="$(existing APP_IP)"; APP_IP="${APP_IP:-$(pick_ip "")}"
BROKER_IP="$(existing BROKER_IP)"; BROKER_IP="${BROKER_IP:-$(pick_ip "$APP_IP")}"

echo "mailcow-mcp"
note "MCP URL:        https://$MCP_HOSTNAME/mcp"
note "app address:    $APP_IP (mailcow network)"
note "broker address: $BROKER_IP (mailcow network; it listens only on the internal network)"

# --- secrets -------------------------------------------------------------------
new_key() {
    if command -v openssl >/dev/null; then
        openssl rand -base64 32 | tr '+/' '-_'
    else
        docker run --rm "$IMAGE:$MCP_VERSION" generate-key
    fi
}

port_suffix=""
[ "$HTTPS_PORT" = "443" ] || port_suffix=":$HTTPS_PORT"

write_file() {  # path mode content
    local path="$1" mode="$2" content="$3"
    if [ -e "$path" ]; then
        note "kept existing  $path"
        return
    fi
    if [ "$APPLY" = 1 ]; then
        (umask 077; printf '%s\n' "$content" >"$path")
        chmod "$mode" "$path"
        note "wrote          $path"
    else
        note "would write    $path"
    fi
}

echo "files"
SHARED_SECRET="$(new_key)"
[ -f "$KIT_DIR/app.env" ] && SHARED_SECRET="$(grep -E '^BROKER_SHARED_SECRET=' "$KIT_DIR/app.env" | cut -d= -f2-)"

write_file "$KIT_DIR/.env" 600 "# compose settings (setup-mailcow.sh)
MCP_VERSION=$MCP_VERSION
MAILCOW_NETWORK=$NETWORK
APP_IP=$APP_IP
BROKER_IP=$BROKER_IP"

write_file "$KIT_DIR/app.env" 600 "# mailcow-mcp app (setup-mailcow.sh). See docs/configuration.md.
MODE=mailcow
PUBLIC_URL=https://$MCP_HOSTNAME
MAILCOW_URL=https://$MAILCOW_HOSTNAME$port_suffix
MAILCOW_INTERNAL_URL=https://nginx-mailcow$port_suffix
MAILCOW_OAUTH_CLIENT_ID=${OAUTH_CLIENT_ID}
MAILCOW_OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
BROKER_URL=http://mcp-broker:8091
BROKER_SHARED_SECRET=$SHARED_SECRET
IMAP_HOST=dovecot-mailcow
SMTP_HOST=postfix-mailcow
TLS_SERVER_NAME=$MAILCOW_HOSTNAME
TRUSTED_PROXIES=$IPV4_NETWORK.0/24
ENC_KEY=$(new_key)"

write_file "$KIT_DIR/broker.env" 600 "# mailcow-mcp broker (setup-mailcow.sh). Holds the mailcow API key.
MAILCOW_API_URL=https://nginx-mailcow$port_suffix
TLS_SERVER_NAME=$MAILCOW_HOSTNAME
MAILCOW_API_KEY=${API_KEY}
BROKER_SHARED_SECRET=$SHARED_SECRET
BROKER_SIGNING_KEY=$(new_key)"

listen_ipv6=""
[ "$ENABLE_IPV6" = "false" ] || listen_ipv6="    listen [::]:${HTTPS_PORT} ssl;"
site="$(sed -e "s|\${HTTPS_PORT}|$HTTPS_PORT|g" -e "s|\${MCP_HOSTNAME}|$MCP_HOSTNAME|g" \
    -e "s|^\${LISTEN_IPV6}$|$listen_ipv6|" "$KIT_DIR/mailcow-mcp.conf.template")"
SITE_FILE="$MAILCOW_DIR/data/conf/nginx/mailcow-mcp.conf"
if [ "$APPLY" = 1 ]; then
    printf '%s\n' "$site" >"$SITE_FILE"
    note "wrote          $SITE_FILE"
else
    note "would write    $SITE_FILE"
fi

# --- what's left to do ---------------------------------------------------------
missing_env=""
grep -qE '^MAILCOW_OAUTH_CLIENT_ID=.+' "$KIT_DIR/app.env" 2>/dev/null || [ -n "$OAUTH_CLIENT_ID" ] \
    || missing_env="$missing_env MAILCOW_OAUTH_CLIENT_ID/_SECRET (app.env)"
grep -qE '^MAILCOW_API_KEY=.+' "$KIT_DIR/broker.env" 2>/dev/null || [ -n "$API_KEY" ] \
    || missing_env="$missing_env MAILCOW_API_KEY (broker.env)"

cat <<EOF

Remaining steps (docs/deploy-mailcow.md explains each):

 1. DNS: A/AAAA record  $MCP_HOSTNAME  →  this server.
EOF
if [[ ",$ADDITIONAL_SAN," == *",$MCP_HOSTNAME,"* ]]; then
    echo " 2. Certificate: $MCP_HOSTNAME is already in ADDITIONAL_SAN."
else
    cat <<EOF
 2. Certificate: in $MAILCOW_DIR/mailcow.conf set
        ADDITIONAL_SAN=${ADDITIONAL_SAN:+$ADDITIONAL_SAN,}$MCP_HOSTNAME
    then in $MAILCOW_DIR run:  docker compose up -d
EOF
fi
cat <<EOF
 3. mailcow UI → System → Configuration → Access → OAuth2 Apps → add a client with redirect URI
        https://$MCP_HOSTNAME/oauth/mailcow/callback
 4. mailcow UI → System → Configuration → Access → Administrators → API: enable the
    read-write key and add to "Allow API access from":  $BROKER_IP
    (keep any addresses already there: mailcow has only one read-write key)
 5. mailcow UI → System → Configuration → Options → Fail2ban parameters → allowlist:  $APP_IP
    (every user's IMAP/SMTP login comes from this address)
EOF
if [ -n "$missing_env" ]; then
    echo " 6. Fill in:$missing_env"
fi
cat <<EOF
 7. Start:  cd $KIT_DIR && docker compose up -d
    Then:   cd $MAILCOW_DIR && docker compose restart nginx-mailcow
 8. Back up ENC_KEY (app.env) and BROKER_SIGNING_KEY (broker.env) somewhere off this server.
 9. Check:  curl -fsS https://$MCP_HOSTNAME/healthz
EOF
if [ "$APPLY" = 0 ]; then
    echo
    echo "Nothing was written. Review the above, then run again with --apply."
fi
