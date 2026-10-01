#!/usr/bin/env bash
# Set up and update mailcow-mcp next to an existing mailcow installation.
#
# Read-only by default: it checks each step of docs/deploy-mailcow.md against mailcow and prints
# what it would write. With --apply it writes .env, app.env and broker.env here and the nginx site
# file into mailcow's data/conf/nginx/. It never changes mailcow.conf or mailcow's compose files,
# and never overwrites existing keys.
#
# Usage:
#   ./setup-mailcow.sh --hostname mcp.example.com [--mailcow-dir /opt/mailcow-dockerized] [--apply]
#       [--oauth-client-id ID --oauth-client-secret SECRET] [--api-key KEY] [--version TAG]
#       [--restart]                 also pull the images and restart (and nginx if its file changed)
#   ./setup-mailcow.sh update [VERSION] [--no-restart]
#                                   install this release's kit (default: the latest) and restart
# --hostname and --mailcow-dir are remembered after the first --apply.
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="nitramxx/mailcow-mcp"
IMAGE="ghcr.io/$REPO"
KIT_FILES="docker-compose.yml mailcow-mcp.conf.template setup-mailcow.sh VERSION"

die() { echo "error: $*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }
usage() {
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}
env_value() {  # env_value file KEY
    if [ -f "$1" ]; then
        grep -E "^$2=" "$1" | tail -n 1 | cut -d= -f2- || true
    fi
}
sha256() { { sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"; } | cut -d' ' -f1; }

# --- update: install another release's kit, then run the setup with it ------------------
if [ "${1:-}" = "update" ]; then
    shift
    target="latest"; restart="--restart"
    while [ $# -gt 0 ]; do
        case "$1" in
            --no-restart) restart=""; shift ;;
            -h|--help) usage 0 ;;
            -*) die "unknown option for update: $1" ;;
            *) target="${1#v}"; shift ;;
        esac
    done
    [ -f "$KIT_DIR/app.env" ] || die "nothing to update yet: run the setup with --apply first"
    command -v curl >/dev/null || die "curl is not installed"
    base="${MCP_KIT_BASE_URL:-https://github.com/$REPO/releases}"
    if [ "$target" = "latest" ]; then url="$base/latest/download/mailcow-kit.tar.gz"
    else url="$base/download/v$target/mailcow-kit.tar.gz"; fi
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    curl -fsSL "$url" -o "$work/kit.tar.gz" || die "can't download $url"
    curl -fsSL "$url.sha256" -o "$work/kit.sha256" || die "can't download $url.sha256"
    [ "$(sha256 "$work/kit.tar.gz")" = "$(cut -d' ' -f1 "$work/kit.sha256")" ] \
        || die "checksum mismatch for $url"
    mkdir "$work/kit"
    tar -xzf "$work/kit.tar.gz" -C "$work/kit"
    for f in $KIT_FILES; do
        [ -f "$work/kit/$f" ] || die "the downloaded kit has no $f"
    done
    old="$(cat "$KIT_DIR/VERSION" 2>/dev/null || echo unknown)"
    new="$(cat "$work/kit/VERSION")"
    echo "kit $old → $new"
    for f in docker-compose.yml mailcow-mcp.conf.template; do
        if ! cmp -s "$KIT_DIR/$f" "$work/kit/$f"; then
            echo "changes in $f:"
            diff -u "$KIT_DIR/$f" "$work/kit/$f" | tail -n +3 | sed 's/^/    /' || true
        fi
    done
    for f in $KIT_FILES; do
        cp "$work/kit/$f" "$KIT_DIR/$f.new"
        mv "$KIT_DIR/$f.new" "$KIT_DIR/$f"
    done
    chmod +x "$KIT_DIR/setup-mailcow.sh"
    # Pin the image to the kit's version.
    if [ -f "$KIT_DIR/.env" ]; then
        sed -i.bak -E "s/^MCP_VERSION=.*/MCP_VERSION=$new/" "$KIT_DIR/.env" && rm -f "$KIT_DIR/.env.bak"
    fi
    echo
    # shellcheck disable=SC2086 # $restart is one flag or nothing
    exec "$KIT_DIR/setup-mailcow.sh" --apply $restart
fi

# --- setup ------------------------------------------------------------------------------
MAILCOW_DIR=""
MCP_HOSTNAME=""
OAUTH_CLIENT_ID=""
OAUTH_CLIENT_SECRET=""
API_KEY=""
MCP_VERSION="$(cat "$KIT_DIR/VERSION" 2>/dev/null || echo latest)"
APPLY=0
RESTART=0

while [ $# -gt 0 ]; do
    case "$1" in
        --hostname) MCP_HOSTNAME="${2:-}"; shift 2 ;;
        --mailcow-dir) MAILCOW_DIR="${2:-}"; shift 2 ;;
        --oauth-client-id) OAUTH_CLIENT_ID="${2:-}"; shift 2 ;;
        --oauth-client-secret) OAUTH_CLIENT_SECRET="${2:-}"; shift 2 ;;
        --api-key) API_KEY="${2:-}"; shift 2 ;;
        --version) MCP_VERSION="${2:-}"; shift 2 ;;
        --apply) APPLY=1; shift ;;
        --restart) RESTART=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown option: $1" >&2; usage 2 ;;
    esac
done
[ "$RESTART" = 0 ] || [ "$APPLY" = 1 ] || die "--restart needs --apply"

# Remembered from the first run.
if [ -z "$MCP_HOSTNAME" ]; then
    public_url="$(env_value "$KIT_DIR/app.env" PUBLIC_URL)"
    MCP_HOSTNAME="${public_url#https://}"
fi
[ -n "$MAILCOW_DIR" ] || MAILCOW_DIR="$(env_value "$KIT_DIR/.env" MAILCOW_DIR)"
[ -n "$MAILCOW_DIR" ] || MAILCOW_DIR="/opt/mailcow-dockerized"

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
MAILCOW_TZ="$(conf TZ UTC)"
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
existing() {
    if [ -f "$KIT_DIR/.env" ]; then
        grep -E "^$1=" "$KIT_DIR/.env" | cut -d= -f2- || true
    fi
}
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

# --- reading mailcow's state (read-only) ------------------------------------------
DBUSER="$(conf DBUSER mailcow)"; DBPASS="$(conf DBPASS)"; DBNAME="$(conf DBNAME mailcow)"
REDISPASS="$(conf REDISPASS)"

in_mailcow() {  # docker compose exec in mailcow's project; fails quietly
    (cd "$MAILCOW_DIR" && docker compose -p "$PROJECT" exec -T "$@") 2>/dev/null
}
sql() {
    local client
    for client in mariadb mysql; do  # newer MariaDB images only have "mariadb"
        if in_mailcow -e MYSQL_PWD="$DBPASS" mysql-mailcow "$client" -u"$DBUSER" "$DBNAME" -N -B -e "$1"; then
            return 0
        fi
    done
    return 1
}
redis() {
    if [ -n "$REDISPASS" ]; then
        in_mailcow -e REDISCLI_AUTH="$REDISPASS" redis-mailcow redis-cli "$@"
    else
        in_mailcow redis-mailcow redis-cli "$@"
    fi
}
ip_in() {  # ip_in IP "list of IPs/CIDRs (any separators)": is IP covered?
    printf '%s\n' "$2" | awk -v ip="$1" '
        function num(a,   p) { split(a, p, "."); return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }
        {
            gsub(/\\n|[ ,;\t]+/, " ")
            n = split($0, items, " ")
            for (i = 1; i <= n; i++) {
                if (items[i] !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) continue
                split(items[i], c, "/"); bits = (c[2] == "" ? 32 : c[2]); size = 2 ^ (32 - bits)
                if (int(num(c[1]) / size) == int(num(ip) / size)) found = 1
            }
        }
        END { exit !found }'
}
resolve() { getent ahosts "$1" 2>/dev/null | awk '{print $1}' | sort -u || true; }

STATUS=(); DETAIL=()
check() { STATUS[$1]="$2"; DETAIL[$1]="$3"; }  # step ok|todo|unknown text

# 1. DNS
mcp_ips="$(resolve "$MCP_HOSTNAME")"
mail_ips="$(resolve "$MAILCOW_HOSTNAME")"
if [ -z "$mcp_ips" ]; then
    check 1 todo "$MCP_HOSTNAME doesn't resolve yet"
elif [ -n "$mail_ips" ] && [ -z "$(comm -23 <(echo "$mcp_ips") <(echo "$mail_ips"))" ]; then
    check 1 ok "$MCP_HOSTNAME → $(echo "$mcp_ips" | tr '\n' ' ')(as $MAILCOW_HOSTNAME)"
else
    check 1 todo "$MCP_HOSTNAME → $(echo "$mcp_ips" | tr '\n' ' '), but $MAILCOW_HOSTNAME → $(echo "$mail_ips" | tr '\n' ' ')"
fi

# 2. Certificate
CERT="$MAILCOW_DIR/data/assets/ssl/cert.pem"
in_san=0; [[ ",${ADDITIONAL_SAN// /}," == *",$MCP_HOSTNAME,"* ]] && in_san=1
if [ -r "$CERT" ] && command -v openssl >/dev/null; then
    if openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -q "DNS:$MCP_HOSTNAME\b"; then
        check 2 ok "mailcow's certificate covers $MCP_HOSTNAME (expires $(openssl x509 -in "$CERT" -noout -enddate | cut -d= -f2))"
    elif [ "$in_san" = 1 ]; then
        check 2 todo "in ADDITIONAL_SAN, but the certificate doesn't include it yet"
    else
        check 2 todo "not in ADDITIONAL_SAN"
    fi
else
    check 2 unknown "can't read $CERT"
fi

# 4. OAuth2 app (and its credentials, if not given)
REDIRECT_URI="https://$MCP_HOSTNAME/oauth/mailcow/callback"
if oauth_row="$(sql "SELECT client_id, client_secret FROM oauth_clients WHERE CONCAT(' ', redirect_uri, ' ') LIKE '% $REDIRECT_URI %' ORDER BY id DESC LIMIT 1")"; then
    if [ -n "$oauth_row" ]; then
        check 4 ok "OAuth2 client $(cut -f1 <<<"$oauth_row") has the redirect URI"
        [ -n "$OAUTH_CLIENT_ID" ] || OAUTH_CLIENT_ID="$(cut -f1 <<<"$oauth_row")"
        [ -n "$OAUTH_CLIENT_SECRET" ] || OAUTH_CLIENT_SECRET="$(cut -f2 <<<"$oauth_row")"
    else
        check 4 todo "no OAuth2 client with redirect URI $REDIRECT_URI"
    fi
else
    check 4 unknown "can't read mailcow's database (is mysql-mailcow running?)"
fi

# 5. API key (and the key itself, if not given)
if api_row="$(sql "SELECT api_key, skip_ip_check, allow_from FROM api WHERE access = 'rw' AND active = 1 LIMIT 1")"; then
    if [ -z "$api_row" ]; then
        check 5 todo "the read-write API key isn't active"
    else
        allow_from="$(cut -f3- <<<"$api_row")"
        if [ "$(cut -f2 <<<"$api_row")" = 1 ] || ip_in "$BROKER_IP" "$allow_from"; then
            check 5 ok "read-write API key active, $BROKER_IP allowed"
            [ -n "$API_KEY" ] || API_KEY="$(cut -f1 <<<"$api_row")"
        else
            check 5 todo "read-write API key active, but $BROKER_IP isn't in \"Allow API access from\""
        fi
    fi
else
    check 5 unknown "can't read mailcow's database"
fi

# 6. Fail2ban allowlist
if allowlist="$(redis HKEYS F2B_WHITELIST)"; then
    if ip_in "$APP_IP" "$allowlist"; then
        check 6 ok "$APP_IP is allowlisted"
    else
        check 6 todo "$APP_IP isn't allowlisted"
    fi
else
    check 6 unknown "can't read mailcow's Redis"
fi

# --- secrets and files ----------------------------------------------------------
new_key() {
    if command -v openssl >/dev/null; then
        openssl rand -base64 32 | tr '+/' '-_'
    else
        docker run --rm "$IMAGE:$MCP_VERSION" generate-key
    fi
}

port_suffix=""
[ "$HTTPS_PORT" = "443" ] || port_suffix=":$HTTPS_PORT"

# Run with sudo, files here still belong to whoever owns this directory (e.g. you, not root).
KIT_OWNER=""
if [ "$(id -u)" = 0 ]; then
    KIT_OWNER="$(stat -c '%u:%g' "$KIT_DIR" 2>/dev/null || stat -f '%u:%g' "$KIT_DIR")"
fi
own() {
    if [ -n "$KIT_OWNER" ]; then
        chown "$KIT_OWNER" "$1"
    fi
}

write_file() {  # path mode content
    local path="$1" mode="$2" content="$3"
    if [ -e "$path" ]; then
        note "kept existing  $path"
        return
    fi
    if [ "$APPLY" = 1 ]; then
        (umask 077; printf '%s\n' "$content" >"$path")
        chmod "$mode" "$path"
        own "$path"
        note "wrote          $path"
    else
        note "would write    $path"
    fi
}
fill_empty() {  # fill_empty file KEY value: set KEY only if it's empty in an existing file
    local file="$1" key="$2" value="$3"
    if ! { [ -f "$file" ] && [ -n "$value" ] && grep -qE "^$key=$" "$file"; }; then
        return 0
    fi
    if [ "$APPLY" = 1 ]; then
        local tmp; tmp="$(mktemp "$file.XXXXXX")"
        awk -v k="$key" -v v="$value" 'BEGIN { FS = OFS = "=" } $1 == k && $2 == "" { print k "=" v; next } { print }' "$file" >"$tmp"
        chmod 600 "$tmp"; own "$tmp"; mv "$tmp" "$file"
        note "filled in      $key ($file)"
    else
        note "would fill in  $key ($file)"
    fi
}

add_missing() {  # add_missing file KEY value: append KEY if an existing file lacks it
    local file="$1" key="$2" value="$3"
    if [ -f "$file" ] && ! grep -qE "^$key=" "$file"; then
        if [ "$APPLY" = 1 ]; then
            printf '%s=%s\n' "$key" "$value" >>"$file"
            note "added          $key ($file)"
        else
            note "would add      $key ($file)"
        fi
    fi
}

echo "files"
SHARED_SECRET="$(new_key)"
[ -f "$KIT_DIR/app.env" ] && SHARED_SECRET="$(grep -E '^BROKER_SHARED_SECRET=' "$KIT_DIR/app.env" | cut -d= -f2-)"

write_file "$KIT_DIR/.env" 600 "# compose settings (setup-mailcow.sh)
MCP_VERSION=$MCP_VERSION
MAILCOW_DIR=$MAILCOW_DIR
MAILCOW_NETWORK=$NETWORK
APP_IP=$APP_IP
BROKER_IP=$BROKER_IP"
add_missing "$KIT_DIR/.env" MAILCOW_DIR "$MAILCOW_DIR"

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
TIMEZONE=$MAILCOW_TZ
ENC_KEY=$(new_key)"
add_missing "$KIT_DIR/app.env" TIMEZONE "$MAILCOW_TZ"
fill_empty "$KIT_DIR/app.env" MAILCOW_OAUTH_CLIENT_ID "$OAUTH_CLIENT_ID"
fill_empty "$KIT_DIR/app.env" MAILCOW_OAUTH_CLIENT_SECRET "$OAUTH_CLIENT_SECRET"

write_file "$KIT_DIR/broker.env" 600 "# mailcow-mcp broker (setup-mailcow.sh). Holds the mailcow API key.
MAILCOW_API_URL=https://nginx-mailcow$port_suffix
TLS_SERVER_NAME=$MAILCOW_HOSTNAME
MAILCOW_API_KEY=${API_KEY}
BROKER_SHARED_SECRET=$SHARED_SECRET
BROKER_SIGNING_KEY=$(new_key)"
fill_empty "$KIT_DIR/broker.env" MAILCOW_API_KEY "$API_KEY"

listen_ipv6=""
[ "$ENABLE_IPV6" = "false" ] || listen_ipv6="    listen [::]:${HTTPS_PORT} ssl;"
site="$(sed -e "s|\${HTTPS_PORT}|$HTTPS_PORT|g" -e "s|\${MCP_HOSTNAME}|$MCP_HOSTNAME|g" \
    -e "s|^\${LISTEN_IPV6}$|$listen_ipv6|" "$KIT_DIR/mailcow-mcp.conf.template")"
SITE_FILE="$MAILCOW_DIR/data/conf/nginx/mailcow-mcp.conf"
site_changed=1
if [ -f "$SITE_FILE" ] && [ "$(cat "$SITE_FILE")" = "$site" ]; then
    site_changed=0
fi
if [ "$APPLY" = 1 ]; then
    printf '%s\n' "$site" >"$SITE_FILE"
    note "wrote          $SITE_FILE"
    # mailcow's nginx sees the file at once (mounted directory): make sure it's valid.
    if nginx_test="$(in_mailcow nginx-mailcow nginx -t 2>&1)" || [ -z "$(cd "$MAILCOW_DIR" && docker compose -p "$PROJECT" ps -q nginx-mailcow 2>/dev/null)" ]; then
        :
    else
        mv "$SITE_FILE" "$SITE_FILE.disabled"
        echo "error: nginx rejects the site file; moved it to $SITE_FILE.disabled:" >&2
        echo "$nginx_test" >&2
    fi
else
    note "would write    $SITE_FILE"
fi

# 7. Credentials in the env files
missing_env=""
oauth_id_set=0; grep -qE '^MAILCOW_OAUTH_CLIENT_ID=.+' "$KIT_DIR/app.env" 2>/dev/null && oauth_id_set=1
[ -n "$OAUTH_CLIENT_ID" ] && oauth_id_set=1
api_key_set=0; grep -qE '^MAILCOW_API_KEY=.+' "$KIT_DIR/broker.env" 2>/dev/null && api_key_set=1
[ -n "$API_KEY" ] && api_key_set=1
[ "$oauth_id_set" = 1 ] || missing_env="$missing_env MAILCOW_OAUTH_CLIENT_ID/_SECRET (app.env)"
[ "$api_key_set" = 1 ] || missing_env="$missing_env MAILCOW_API_KEY (broker.env)"
if [ -z "$missing_env" ]; then
    check 7 ok "OAuth2 client and API key are set"
else
    check 7 todo "missing:$missing_env"
fi

# --restart: pull and (re)start; nginx only when its site file changed.
if [ "$RESTART" = 1 ]; then
    echo "restarting"
    (cd "$KIT_DIR" && docker compose pull -q && docker compose up -d --remove-orphans) \
        || die "docker compose failed in $KIT_DIR"
    if [ "$site_changed" = 1 ] && [ -f "$SITE_FILE" ]; then
        (cd "$MAILCOW_DIR" && docker compose -p "$PROJECT" restart nginx-mailcow) >/dev/null 2>&1 \
            && note "restarted nginx-mailcow (its site file changed)"
    fi
    for _ in $(seq 45); do
        states="$(docker compose --project-directory "$KIT_DIR" ps --format '{{.Service}}={{.Health}}' 2>/dev/null)" || states=""
        if grep -q "^app=healthy" <<<"$states" && grep -q "^broker=healthy" <<<"$states"; then
            break
        fi
        sleep 2
    done
fi

# 9. Running
running=""
if [ -f "$KIT_DIR/.env" ]; then
    running="$(docker compose --project-directory "$KIT_DIR" ps --format '{{.Service}}={{.Health}}' 2>/dev/null)" || running=""
fi
if grep -q "^app=healthy" <<<"$running" && grep -q "^broker=healthy" <<<"$running"; then
    health="$(curl -fsS -m 10 --resolve "$MCP_HOSTNAME:$HTTPS_PORT:127.0.0.1" "https://$MCP_HOSTNAME:$HTTPS_PORT/healthz" 2>/dev/null)" || health=""
    api_check="$(docker compose --project-directory "$KIT_DIR" exec -T broker mailcow-mcp check-mailcow 2>&1)" || true
    if [ -n "$health" ] && ! grep -q '"broker":"ok"' <<<"$health"; then
        check 9 todo "the app can't reach the broker (BROKER_URL in app.env must be http://mcp-broker:8091, as in docker-compose.yml)"
    elif ! grep -q "mailcow API: ok" <<<"$api_check"; then
        check 9 todo "the broker can't use the mailcow API: ${api_check#mailcow-mcp: }"
    elif [ -n "$health" ]; then
        check 9 ok "app and broker healthy; https://$MCP_HOSTNAME/healthz answers through mailcow's nginx"
    else
        check 9 todo "app and broker healthy, but mailcow's nginx doesn't route $MCP_HOSTNAME yet"
    fi
elif [ -n "$running" ]; then
    check 9 todo "containers: $(echo "$running" | tr '\n' ' ')"
else
    check 9 todo "not started"
fi

# --- report ---------------------------------------------------------------------
echo
echo "checks"
for step in 1 2 4 5 6 7 9; do  # the guide's step numbers
    case "${STATUS[$step]}" in
        ok) mark="✓" ;; todo) mark="✗" ;; *) mark="?" ;;
    esac
    printf '  %s %s. %s\n' "$mark" "$step" "${DETAIL[$step]}"
done

todo() { [ "${STATUS[$1]}" != ok ]; }
echo
echo "To do (docs/deploy-mailcow.md explains each step):"
if todo 1; then
    echo " 1. DNS: A/AAAA record  $MCP_HOSTNAME  →  this server (same addresses as $MAILCOW_HOSTNAME)."
fi
if todo 2; then
    if [ "$in_san" = 1 ]; then
        cat <<EOF
 2. Certificate: renew it, in $MAILCOW_DIR:  docker compose up -d
    (DNS must resolve first; follow with  docker compose logs --tail=50 acme-mailcow)
EOF
    else
        cat <<EOF
 2. Certificate: in $MAILCOW_DIR/mailcow.conf set
        ADDITIONAL_SAN=${ADDITIONAL_SAN:+$ADDITIONAL_SAN,}$MCP_HOSTNAME
    then in $MAILCOW_DIR run:  docker compose up -d
EOF
    fi
fi
if todo 4; then
    cat <<EOF
 4. mailcow UI → System → Configuration → Access → OAuth2 Apps → add a client with redirect URI
        $REDIRECT_URI
EOF
fi
if todo 5; then
    cat <<EOF
 5. mailcow UI → System → Configuration → Access → Administrators → API: activate the
    read-write key and add to "Allow API access from":  $BROKER_IP
    (keep any addresses already there: mailcow has only one read-write key)
EOF
fi
if todo 6; then
    cat <<EOF
 6. mailcow UI → System → Configuration → Options → Fail2ban parameters → allowlist:  $APP_IP
    (every user's IMAP/SMTP login comes from this address)
EOF
fi
if todo 7; then
    echo " 7. Run this again after steps 4 and 5 (it reads the values from mailcow), or fill in:$missing_env"
fi
if todo 9; then
    if [ ! -f "$KIT_DIR/app.env" ]; then
        echo " 7. Write the files: run this again with --apply. Then:"
    fi
    cat <<EOF
 7. Start:  cd $KIT_DIR && docker compose up -d
    Then:   cd $MAILCOW_DIR && docker compose restart nginx-mailcow
EOF
fi
cat <<EOF
 8. Back up ENC_KEY (app.env) and BROKER_SIGNING_KEY (broker.env) somewhere off this server.
EOF
if [ "$APPLY" = 0 ]; then
    echo
    echo "Nothing was written. Review the above, then run again with --apply."
fi
