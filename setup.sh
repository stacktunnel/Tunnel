#!/usr/bin/env bash
# StackTunnel installer / manager
# Usage:  sudo bash setup.sh
# The binary is downloaded from GitHub Releases automatically (and verified with
# SHA256SUMS). To install offline, put a binary named "stacktunnel" next to this script.

set -u

SERVICE="stacktunnel"
BIN="/usr/local/bin/stacktunnel"
CONF_DIR="/etc/stacktunnel"
CONF="$CONF_DIR/config.env"
UNIT="/etc/systemd/system/${SERVICE}.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Standalone ws services (see do_add_ws_service) are named instances:
# stacktunnel-ws-<name>.service / config-ws-<name>.env under $CONF_DIR -
# separate from $SERVICE, and from each other.

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[36m'; N=$'\e[0m'
info() { echo "${B}[i]${N} $*"; }
ok()   { echo "${G}[OK]${N} $*"; }
warn() { echo "${Y}[!]${N} $*"; }
err()  { echo "${R}[X]${N} $*"; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Run this script as root:  sudo bash $0"
    exit 1
  fi
}

# ---------- input helpers ----------

ask() { # ask "prompt" "default" -> echoes answer
  local prompt="$1" def="${2:-}" ans
  if [[ -n "$def" ]]; then
    read -r -p "$prompt [$def]: " ans </dev/tty
    echo "${ans:-$def}"
  else
    read -r -p "$prompt: " ans </dev/tty
    echo "$ans"
  fi
}

confirm() { # confirm "question" y|n
  local def="${2:-y}" ans
  read -r -p "$1 [$( [[ $def == y ]] && echo Y/n || echo y/N )]: " ans </dev/tty
  ans="${ans:-$def}"
  [[ "$ans" =~ ^[Yy] ]]
}

valid_ports() { [[ "$1" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]]; }

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

expand_ports() {
  local item
  IFS=',' read -ra items <<<"$1"
  for item in "${items[@]}"; do
    if [[ "$item" == *-* ]]; then seq "${item%-*}" "${item#*-}"; else echo "$item"; fi
  done
}

ask_ports() { # ask_ports "prompt" [empty] -> echoes list (empty or "0" allowed if 2nd arg = empty)
  local v
  while true; do
    v="$(ask "$1")"
    v="${v// /}"
    if [[ ( -z "$v" || "$v" == "0" ) && "${2:-}" == "empty" ]]; then echo ""; return; fi
    if valid_ports "$v"; then
      local bad=0 item lo hi
      IFS=',' read -ra items <<<"$v"
      for item in "${items[@]}"; do
        lo="${item%-*}"; hi="${item#*-}"
        if (( lo < 1 || hi > 65535 || lo > hi || hi - lo > 2000 )); then bad=1; fi
      done
      if (( bad == 0 )); then echo "$v"; return; fi
    fi
    err "Invalid input. Example: 443,2053,8000-8100 (max 2000 ports per range)" >&2
  done
}

gen_key() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 24
  else head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

# ---------- binary ----------

REPO="${STACKTUNNEL_REPO:-stacktunnel/Tunnel}"
if [[ -n "${STACKTUNNEL_BASE_URL:-}" ]]; then
  BASE_URL="$STACKTUNNEL_BASE_URL"
elif [[ -n "${STACKTUNNEL_VERSION:-}" ]]; then
  BASE_URL="https://github.com/${REPO}/releases/download/${STACKTUNNEL_VERSION}"
else
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
fi

fetch() { # fetch URL OUTFILE
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq curl >/dev/null 2>&1
  fi
  if command -v curl >/dev/null 2>&1; then curl -fsSL --max-time 300 -o "$2" "$1"
  else wget -q -T 300 -O "$2" "$1"; fi
}

download_binary() {
  local arch asset tmp expected actual
  case "$(uname -m)" in
    x86_64|amd64)  arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l)        arch=armv7 ;;
    *) err "Unsupported CPU architecture: $(uname -m)"; return 1 ;;
  esac
  asset="stacktunnel-linux-${arch}"
  tmp="$(mktemp -d)"

  info "Downloading ${BASE_URL}/${asset} ..."
  if ! fetch "${BASE_URL}/${asset}" "$tmp/$asset" || ! fetch "${BASE_URL}/SHA256SUMS" "$tmp/SHA256SUMS"; then
    err "Download failed (github.com may be unreachable from this server)."
    echo "   Workaround: download '${asset}' on a machine that can reach GitHub, then copy it"
    echo "   to this server next to setup.sh, renamed to 'stacktunnel', and run setup.sh again:"
    echo "     scp ${asset} root@THIS_SERVER:~/stacktunnel"
    rm -rf "$tmp"
    return 1
  fi

  expected="$(awk -v f="$asset" '$2==f || $2==("*" f) {print $1}' "$tmp/SHA256SUMS")"
  actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
  if [[ -z "$expected" || "$expected" != "$actual" ]]; then
    err "Checksum verification FAILED for ${asset}. The file was not installed."
    rm -rf "$tmp"
    return 1
  fi

  install -m 0755 "$tmp/$asset" "$BIN"
  rm -rf "$tmp"
  ok "Downloaded and verified ${asset}"
}

install_binary() { # install_binary [force]  (force = always download)
  if [[ "${1:-}" != "force" ]]; then
    local f
    for f in stacktunnel StackTunnel tunnel; do
      if [[ -f "$SCRIPT_DIR/$f" ]]; then
        install -m 0755 "$SCRIPT_DIR/$f" "$BIN"
        ok "Installed local binary: $SCRIPT_DIR/$f"
        return 0
      fi
    done
  fi
  download_binary
}

# ---------- firewall ----------

open_firewall() { # tcp_list udp_list tunnel_port
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    info "ufw is active."
    if confirm "Open the required ports in ufw?" y; then
      local item
      [[ -n "${3:-}" ]] && ufw allow "${3}/tcp" >/dev/null && ok "tcp ${3} opened"
      IFS=',' read -ra t <<<"$1"
      for item in "${t[@]}"; do [[ -n "$item" ]] && ufw allow "${item//-/:}/tcp" >/dev/null && ok "tcp $item opened"; done
      IFS=',' read -ra u <<<"$2"
      for item in "${u[@]}"; do [[ -n "$item" ]] && ufw allow "${item//-/:}/udp" >/dev/null && ok "udp $item opened"; done
    fi
  else
    warn "ufw is not active. If you use another firewall (or a provider firewall), open the ports above yourself."
  fi
}

# ---------- install ----------

do_install() {
  echo
  echo "${B}====== Tunnel setup ======${N}"
  echo "What is the role of THIS server?"
  echo "  1) Iran server    (users connect to it, it accepts the tunnel)"
  echo "  2) Kharej server  (connects to the Iran server, real service runs here)"
  local role
  while true; do
    role="$(ask "Choice (1 or 2)")"
    [[ "$role" == 1 || "$role" == 2 ]] && break
    err "Enter 1 or 2"
  done

  if systemctl list-unit-files 2>/dev/null | grep -q "^${SERVICE}.service"; then
    warn "Service already installed; stopping it to reconfigure."
    systemctl stop "$SERVICE" 2>/dev/null || true
  fi

  local key tun_port tcp_ports udp_ports pad conns rotate iran_ip mode

  if [[ "$role" == 1 ]]; then
    mode="server"
    echo
    info "Shared key: must be EXACTLY the same on the Iran and all Kharej servers."
    if confirm "Generate a random key?" y; then
      key="$(gen_key)"
      echo "   Your key:  ${G}${key}${N}"
      warn "Write this key down now; you need it on the Kharej server."
    else
      key="$(ask "Enter the key")"
    fi
    while true; do
      tun_port="$(ask "Tunnel port (the Kharej server connects to this)" 4000)"
      valid_port "$tun_port" && break
      err "Invalid port"
    done
    echo
    info "Ports that users connect to (opened on this server)."
    tcp_ports="$(ask_ports "TCP ports (e.g. 443,2053,8000-8100; type 0 for none)" empty)"
    udp_ports="$(ask_ports "UDP ports (optional, e.g. 51820; empty = none)" empty)"
    if [[ -z "$tcp_ports" && -z "$udp_ports" ]]; then
      err "At least one TCP or UDP port is required."; return 1
    fi
  else
    mode="client"
    info "You can enter several Iran servers separated by commas (e.g. 1.2.3.4,5.6.7.8)."
    info "Use IP:port for an Iran server with a different tunnel port (e.g. 1.2.3.4,5.6.7.8:4001)."
    iran_ip="$(ask "Iran server IP(s)")"
    iran_ip="${iran_ip// /}"
    while [[ -z "$iran_ip" ]]; do iran_ip="$(ask "Iran server IP(s)")"; iran_ip="${iran_ip// /}"; done
    while true; do
      tun_port="$(ask "Default tunnel port (used for entries without :port)" 4000)"
      valid_port "$tun_port" && break
      err "Invalid port"
    done
    key="$(ask "Shared key (same as on the Iran server)")"
    while [[ -z "$key" ]]; do key="$(ask "Shared key")"; done
    echo
    info "Ports the real service listens on here (127.0.0.1)."
    info "With several Kharej servers, each one lists only its own ports."
    tcp_ports="$(ask_ports "TCP ports (type 0 for none)" empty)"
    udp_ports="$(ask_ports "UDP ports (optional; empty = none)" empty)"
    if [[ -z "$tcp_ports" && -z "$udp_ports" ]]; then
      err "At least one TCP or UDP port is required."; return 1
    fi
    conns="$(ask "Parallel tunnel connections (4-8 for better speed)" 4)"
    [[ "$conns" =~ ^[0-9]+$ ]] && (( conns >= 1 && conns <= 32 )) || conns=4
    rotate="$(ask "Proactively rotate each connection every (e.g. 5m, 3m, 0 to disable)" "5m")"
    [[ "$rotate" =~ ^([0-9]+(s|m|h))$|^0$ ]] || rotate="5m"
    [[ "$rotate" == "0" ]] && rotate="0s"
  fi

  pad="$(ask "Max random padding per frame in bytes (0 = off)" 128)"
  [[ "$pad" =~ ^[0-9]+$ ]] && (( pad <= 4096 )) || pad=128

  # ----- Iran-side checks -----
  if [[ "$mode" == "server" ]]; then
    local all_t all_u listening_t listening_u conflicts=""
    all_t="$( [[ -n "$tcp_ports" ]] && expand_ports "$tcp_ports" )"
    all_u="$( [[ -n "$udp_ports" ]] && expand_ports "$udp_ports" )"
    if grep -qx "22" <<<"$all_t"; then
      warn "Port 22 (SSH) is in the list! You may lock yourself out of SSH."
      confirm "Are you sure?" n || return 1
    fi
    if grep -qx "$tun_port" <<<"$all_t"; then
      err "Tunnel port ($tun_port) must not be one of the user ports."; return 1
    fi
    listening_t="$(ss -Hltn 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u)"
    listening_u="$(ss -Hlun 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -u)"
    while read -r p; do
      [[ -n "$p" ]] && grep -qx "$p" <<<"$listening_t" && conflicts+=" tcp/$p"
    done <<<"$all_t"
    while read -r p; do
      [[ -n "$p" ]] && grep -qx "$p" <<<"$listening_u" && conflicts+=" udp/$p"
    done <<<"$all_u"
    grep -qx "$tun_port" <<<"$listening_t" && conflicts+=" tcp/$tun_port(tunnel)"
    if [[ -n "$conflicts" ]]; then
      warn "These ports are already in use by another service:${conflicts}"
      echo "   The tunnel cannot bind them until you stop that service."
      confirm "Continue anyway?" n || return 1
    fi
  fi

  # ----- binary -----
  install_binary || return 1

  # ----- build command line -----
  local args
  if [[ "$mode" == "server" ]]; then
    args="-mode server -key ${key} -tunnel :${tun_port} -pad ${pad}"
  else
    local targets="" e
    IFS=',' read -ra ents <<<"$iran_ip"
    for e in "${ents[@]}"; do
      [[ "$e" == *:* ]] || e="${e}:${tun_port}"
      targets+="${targets:+,}${e}"
    done
    args="-mode client -key ${key} -tunnel ${targets} -pad ${pad} -conns ${conns} -rotate ${rotate}"
  fi
  [[ -n "$tcp_ports" ]] && args+=" -ports ${tcp_ports}"
  [[ -n "$udp_ports" ]] && args+=" -udp ${udp_ports}"

  # ----- save config -----
  mkdir -p "$CONF_DIR"
  umask 077
  cat >"$CONF" <<EOF
MODE=${mode}
KEY=${key}
TUNNEL_PORT=${tun_port}
IRAN_IP=${targets:-}
TCP_PORTS=${tcp_ports}
UDP_PORTS=${udp_ports}
PAD=${pad}
CONNS=${conns:-}
ROTATE=${rotate:-}
EOF
  chmod 600 "$CONF"

  # ----- systemd unit -----
  cat >"$UNIT" <<EOF
[Unit]
Description=StackTunnel (${mode})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN} ${args}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  chmod 600 "$UNIT"
  ok "Service file created: $UNIT"

  # ----- firewall -----
  if [[ "$mode" == "server" ]]; then
    echo
    open_firewall "$tcp_ports" "$udp_ports" "$tun_port"
  fi

  # ----- start -----
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1
  systemctl restart "$SERVICE"
  sleep 3

  echo
  if systemctl is-active --quiet "$SERVICE"; then
    ok "Service is running and will start automatically after reboot."
  else
    err "Service failed to start. Log:"
    journalctl -u "$SERVICE" -n 20 --no-pager
    return 1
  fi
  journalctl -u "$SERVICE" -n 8 --no-pager | sed 's/^/   /'

  # ----- next steps -----
  echo
  echo "${B}====== Next steps ======${N}"
  if [[ "$mode" == "server" ]]; then
    echo "1) On the Kharej server run this script, choose 2 (Kharej server) and enter:"
    echo "     Iran server IP : (the IP of this server)"
    echo "     Tunnel port    : ${tun_port}"
    echo "     Key            : ${key}"
    [[ -n "$tcp_ports" ]] && echo "     TCP ports      : ${tcp_ports}"
    [[ -n "$udp_ports" ]] && echo "     UDP ports      : ${udp_ports}"
    echo "2) Any old service that used these ports on THIS server must be stopped."
    echo "3) When the Kharej server connects, this server's log shows:"
    echo "     tunnel up from ...    (command: bash $0 logs)"
    echo "4) Users keep their old configs, pointing at this server's IP and ports."
  else
    echo "1) Make sure the real service (xray, x-ui, ...) on this server listens on:"
    echo "     ${tcp_ports:+TCP: ${tcp_ports}  }${udp_ports:+UDP: ${udp_ports}}"
    echo "2) This server's log should show one line per Iran server:  connected to <IP>:<port>"
    echo "   If you keep seeing 'disconnected': check Iran IP/port, key, and the Iran firewall."
    echo "3) Start order does not matter; the client retries automatically."
    echo
    info "Testing reachability of the Iran tunnel port..."
    local host port
    for e in "${ents[@]}"; do
      if [[ "$e" == *:* ]]; then host="${e%:*}"; port="${e##*:}"; else host="$e"; port="$tun_port"; fi
      if timeout 5 bash -c "</dev/tcp/${host}/${port}" 2>/dev/null; then
        ok "${host}:${port} is reachable."
      else
        warn "Cannot reach ${host}:${port}. Is that Iran server running and the port open?"
      fi
    done
  fi
  echo
  echo "Manage with:  bash $0 status | logs | restart | update | tune | window N | show | uninstall"
}

# ---------- manage ----------

do_status() {
  if [[ ! -f "$UNIT" ]]; then err "Service is not installed."; return 1; fi
  systemctl --no-pager status "$SERVICE" | head -n 12
  echo
  echo "Version: $("$BIN" -version 2>/dev/null || echo unknown)"
  echo
  if [[ -f "$CONF" ]]; then
    # shellcheck disable=SC1090
    source "$CONF"
    echo "Role: $MODE"
    if [[ "$MODE" == "server" ]]; then
      echo "Listening ports:"
      ss -Hltnup 2>/dev/null | grep stacktunnel | awk '{print "  "$1, $5}'
    fi
  fi
  echo
  journalctl -u "$SERVICE" -n 10 --no-pager
  local f name
  for f in /etc/systemd/system/stacktunnel-ws-*.service; do
    [[ -e "$f" ]] || continue
    name="$(basename "$f" .service)"
    echo
    echo "${B}--- ${name} (standalone) ---${N}"
    systemctl --no-pager status "$name" | head -n 6
    journalctl -u "$name" -n 6 --no-pager
  done
}

# ---------- extra transports ----------
#
# main.go (0.4.0+) can run several transports (tcp, udp, ws) at once INSIDE
# ONE process, all feeding the same pool, with the exposed user-facing
# ports bound exactly once - that's what actually gives automatic failover:
# if one transport gets blocked, traffic keeps moving over whichever other
# one still gets through, with no further action needed.
#
# An earlier version of this did it by running a second, fully separate
# stacktunnel process (its own systemd unit) per extra transport. That
# cannot work: each process has its own pool, so the two could never join
# the same failover group, and both tried to bind the very same exposed
# TCP ports, which crash-loops with "address already in use" the moment
# both are enabled. This replaces that approach: adding a transport now
# edits the ONE existing service's -transport list in place and restarts
# it, instead of creating a second unit.

set_conf_var() { # set_conf_var NAME VALUE -- upserts NAME=VALUE in $CONF
  local name="$1" val="$2"
  if grep -q "^${name}=" "$CONF" 2>/dev/null; then
    sed -i "s|^${name}=.*|${name}=${val}|" "$CONF"
  else
    echo "${name}=${val}" >>"$CONF"
  fi
}

set_unit_flag() { # set_unit_flag -flag value -- upserts "-flag value" on $UNIT's ExecStart line
  local flag="$1" val="$2"
  if grep -qF -- "${flag} " "$UNIT"; then
    sed -i -E "s|${flag} [^ ]*|${flag} ${val}|" "$UNIT"
  else
    sed -i -E "s|^(ExecStart=.*)|\1 ${flag} ${val}|" "$UNIT"
  fi
}

# update_transport NAME -- adds NAME to the -transport list on $UNIT's
# ExecStart line (deduplicated) and echoes the resulting list.
update_transport() {
  local newname="$1" execline current newlist
  execline="$(grep '^ExecStart=' "$UNIT")"
  current="$(echo "$execline" | grep -oE -- '-transport [^ ]+' | awk '{print $2}')"
  [[ -z "$current" ]] && current="tcp"
  if [[ ",${current}," == *",${newname},"* ]]; then
    echo "$current"
    return 0
  fi
  newlist="${current},${newname}"
  if echo "$execline" | grep -qE -- '-transport [^ ]+'; then
    sed -i -E "s|-transport [^ ]+|-transport ${newlist}|" "$UNIT"
  else
    sed -i -E "s|^(ExecStart=.*)|\1 -transport ${newlist}|" "$UNIT"
  fi
  echo "$newlist"
}

do_add_transport() {
  local name="$1" current
  [[ -f "$UNIT" ]] || { err "Service is not installed. Run: sudo bash $0 install"; return 1; }
  [[ -f "$CONF" ]] || { err "No config found - run 'install' first."; return 1; }
  # shellcheck disable=SC1090
  source "$CONF"

  current="$(grep '^ExecStart=' "$UNIT" | grep -oE -- '-transport [^ ]+' | awk '{print $2}')"
  [[ -z "$current" ]] && current="tcp"
  if [[ ",${current}," == *",${name},"* ]]; then
    ok "${name} is already enabled on this service (-transport ${current})."
    return 0
  fi

  case "$name" in
    udp)
      : # tcp and udp are different OS-level sockets, so they share the
        # same -tunnel address/port with no conflict.
      ;;
    ws)
      echo
      info "ws is a real TLS+WebSocket connection - meant to look like an ordinary"
      info "HTTPS visit, and to sit behind something that already looks like one"
      info "(a CDN edge, or e.g. nginx inside Google Cloud Run/ArvanCloud forwarding"
      info "to this server). This is the transport to use as a shutdown-period"
      info "fallback - and unlike tcp/udp, which side DIALS and which LISTENS for"
      info "it is a real choice, not fixed by whether this machine is server/client:"
      info "whichever side has the restrictive egress (usually the Iran server)"
      info "should be the one that DIALS OUT through the CDN/front; the other side"
      info "(usually the kharej/outside server, behind its own nginx) LISTENS."
      echo
      local ws_role
      ws_role=$(ask "On THIS machine, should ws dial out (d) or listen (l)? [d/l]" \
        "$([[ "$MODE" == "client" ]] && echo d || echo l)")
      local ws_path
      ws_path=$(ask "HTTP path for the WebSocket upgrade" "${WS_PATH:-/}")
      set_unit_flag -ws-path "$ws_path"
      set_conf_var WS_PATH "$ws_path"

      # ws-reverse is only needed when this role disagrees with what -mode
      # would normally do on its own (client dials, server listens).
      local reverse=false
      { [[ "$MODE" == "client" && "$ws_role" == l* ]] || [[ "$MODE" == "server" && "$ws_role" == d* ]]; } && reverse=true

      if [[ "$ws_role" == d* ]]; then
        local ws_host ws_port
        ws_host=$(ask "Public hostname to dial (SNI = Host), e.g. myapp-xyz.run.app or api.yourdomain" "${WS_HOST:-}")
        [[ -z "$ws_host" ]] && { err "A host to dial is required."; return 1; }
        ws_port=$(ask "Port" "${WS_PORT:-443}")
        set_unit_flag -ws-host "$ws_host"
        set_unit_flag -ws-port "$ws_port"
        set_conf_var WS_HOST "$ws_host"
        set_conf_var WS_PORT "$ws_port"
      else
        local tls_yn
        echo "Does THIS machine terminate TLS itself, or does something in front of it"
        echo "(your own nginx, a CDN, a load balancer) already terminate TLS before"
        echo "forwarding here?"
        tls_yn=$(ask "Terminate TLS on this machine itself? [y/N]" "n")
        if [[ "$tls_yn" =~ ^[Yy] ]]; then
          local ws_cert ws_key
          ws_cert=$(ask "Path to TLS certificate file")
          ws_key=$(ask "Path to TLS private key file")
          set_unit_flag -ws-cert "$ws_cert"
          set_unit_flag -ws-key "$ws_key"
          set_conf_var WS_CERT "$ws_cert"
          set_conf_var WS_KEY "$ws_key"
        fi
        local listen_default="127.0.0.1:8080"
        if [[ "$reverse" == true ]]; then
          # This is a client-mode machine listening for ws (reversed): -tunnel
          # here is the comma-separated dial target list for tcp/udp, not a
          # usable listen address, so always ask explicitly.
          listen_default="127.0.0.1:8081"
        elif [[ ",${current}," == *",tcp,"* ]]; then
          warn "tcp is also enabled: ws can't bind the same address/port as tcp on this server."
        fi
        if [[ "$reverse" == true || ",${current}," == *",tcp,"* ]]; then
          local ws_listen
          ws_listen=$(ask "Local address for the ws listener (nginx/the CDN forwards here)" "${WS_LISTEN:-$listen_default}")
          set_unit_flag -ws-listen "$ws_listen"
          set_conf_var WS_LISTEN "$ws_listen"
        fi
      fi

      if [[ "$reverse" == true ]]; then
        # -ws-reverse is a bool flag: Go's flag package does NOT consume a
        # following argument for those, so this must land as one token
        # ("-ws-reverse=true"), not "-ws-reverse true" via set_unit_flag's
        # normal space-joined convention (that would leave a stray "true"
        # token and silently stop parsing anything listed after it).
        grep -qF -- "-ws-reverse=true" "$UNIT" || sed -i -E "s|^(ExecStart=.*)|\1 -ws-reverse=true|" "$UNIT"
        set_conf_var WS_REVERSE true
      fi
      ;;
    *)
      err "Unknown transport: $name"
      return 1
      ;;
  esac

  local newlist
  newlist="$(update_transport "$name")"
  systemctl daemon-reload
  systemctl restart "$SERVICE"
  sleep 2

  if systemctl is-active --quiet "$SERVICE"; then
    ok "${SERVICE} is now running with -transport ${newlist} - failover between them is automatic."
  else
    err "${SERVICE} failed to start with -transport ${newlist}. Log:"
    journalctl -u "$SERVICE" -n 20 --no-pager
    return 1
  fi

  if [[ "$MODE" == "server" && "$name" == "udp" ]] && command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow "${TUNNEL_PORT}/udp" >/dev/null 2>&1 && ok "Opened ${TUNNEL_PORT}/udp in ufw."
  fi
}

# do_remove_transport NAME -- drops NAME from the primary service's
# -transport list and restarts it. Used to undo do_add_transport (e.g. to
# move ws out to its own standalone service via do_add_ws_service instead).
do_remove_transport() {
  local name="$1" current newlist
  [[ -f "$UNIT" ]] || { err "Service is not installed."; return 1; }
  current="$(grep '^ExecStart=' "$UNIT" | grep -oE -- '-transport [^ ]+' | awk '{print $2}')"
  [[ -z "$current" ]] && current="tcp"
  if [[ ",${current}," != *",${name},"* ]]; then
    ok "${name} is not in this service's -transport list (${current}) - nothing to do."
    return 0
  fi
  newlist="$(echo "$current" | tr ',' '\n' | grep -vx "$name" | paste -sd, -)"
  [[ -z "$newlist" ]] && newlist="tcp"
  sed -i -E "s|-transport [^ ]+|-transport ${newlist}|" "$UNIT"
  systemctl daemon-reload
  systemctl restart "$SERVICE"
  sleep 2
  if systemctl is-active --quiet "$SERVICE"; then
    ok "${SERVICE} is now running with -transport ${newlist}."
  else
    err "${SERVICE} failed to start with -transport ${newlist}. Log:"
    journalctl -u "$SERVICE" -n 20 --no-pager
    return 1
  fi
}

# ---------- standalone ws service(s) ----------
#
# do_add_transport (above) merges ws into the SAME process/pool as tcp/udp,
# so the Go code's own failover picks between them automatically on every
# forwarded connection - no outside signal needed, but also no way to see
# or choose which transport a given connection used.
#
# This instead sets up ws as a genuinely SEPARATE stacktunnel process, with
# its OWN exposed port(s), independent of the primary tcp/udp service (no
# port conflict, since they're different ports; no shared pool, since they
# don't need one). That lets you wire ws up as its own outbound/inbound in
# your own panel (e.g. a second x-ui inbound pointed at its port) and switch
# between them with your panel's own balancer instead of this program's.
#
# Each instance is named (e.g. "arvan", "aws", "cloudrun") so you can run
# several at once - one per front/provider, each its own
# stacktunnel-ws-<name> service, own unit, own port(s), own -ws-host.

ws_instance_unit() { echo "/etc/systemd/system/stacktunnel-ws-${1}.service"; }
ws_instance_conf() { echo "${CONF_DIR}/config-ws-${1}.env"; }

do_list_ws_services() {
  local f name found=0
  for f in /etc/systemd/system/stacktunnel-ws-*.service; do
    [[ -e "$f" ]] || continue
    found=1
    name="$(basename "$f" .service)"
    name="${name#stacktunnel-ws-}"
    local active; active="$(systemctl is-active "stacktunnel-ws-${name}" 2>/dev/null || echo unknown)"
    echo "  - ${name}  (stacktunnel-ws-${name}.service, ${active})"
  done
  [[ "$found" == 0 ]] && echo "  (none yet)"
}

do_remove_ws_service() {
  local name="$1" unit conf
  [[ -z "$name" ]] && { err "Usage: remove-ws-service NAME"; return 1; }
  unit="$(ws_instance_unit "$name")"; conf="$(ws_instance_conf "$name")"
  [[ -f "$unit" ]] || { err "No such ws service: ${name}"; return 1; }
  systemctl disable --now "stacktunnel-ws-${name}" 2>/dev/null
  rm -f "$unit" "$conf"
  systemctl daemon-reload
  ok "Removed stacktunnel-ws-${name}."
}

do_add_ws_service() {
  [[ -f "$UNIT" ]] || { err "Install the primary service first (option 1)."; return 1; }
  [[ -f "$CONF" ]] || { err "No config found - run 'install' first."; return 1; }
  # shellcheck disable=SC1090
  source "$CONF"

  echo
  info "This sets ws up as its OWN standalone service, with its own port(s),"
  info "fully separate from the ${SERVICE} service (tcp/udp) you already have."
  info "Point a separate outbound/inbound at it (e.g. a second x-ui inbound on"
  info "its port) and switch between them yourself - this is independent of"
  info "the -transport tcp,udp,ws failover from option 10/enable-ws."
  echo
  info "Existing standalone ws services:"
  do_list_ws_services
  echo

  local name="${1:-}"
  while [[ -z "$name" || ! "$name" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]]; do
    name=$(ask "Short name for THIS one (lowercase letters/digits/hyphens, e.g. arvan, aws, cloudrun)")
  done
  local WS_SERVICE="stacktunnel-ws-${name}"
  local WS_UNIT; WS_UNIT="$(ws_instance_unit "$name")"
  local WS_CONF; WS_CONF="$(ws_instance_conf "$name")"

  if [[ -f "$WS_UNIT" ]]; then
    warn "${WS_SERVICE} already exists; stopping it to reconfigure."
    systemctl stop "$WS_SERVICE" 2>/dev/null || true
  fi

  local ws_role will_dial=false reverse=false
  ws_role=$(ask "On THIS machine, should ws dial out (d) or listen (l)? [d/l]" \
    "$([[ "$MODE" == "client" ]] && echo d || echo l)")
  [[ "$ws_role" == d* ]] && will_dial=true
  { [[ "$MODE" == "client" && "$will_dial" == false ]] || [[ "$MODE" == "server" && "$will_dial" == true ]]; } && reverse=true

  local ws_path
  ws_path=$(ask "HTTP path for the WebSocket upgrade" "/tun")

  local tcp_ports udp_ports
  if [[ "$MODE" == "server" ]]; then
    echo
    info "Ports that users connect to for THIS ws path (opened on this server)."
    tcp_ports="$(ask_ports "TCP ports for ws (e.g. 8890; type 0 for none)" empty)"
    udp_ports="$(ask_ports "UDP ports for ws (optional; empty = none)" empty)"
  else
    echo
    info "Ports the real service listens on here (127.0.0.1), for THIS ws path."
    tcp_ports="$(ask_ports "TCP ports (type 0 for none)" empty)"
    udp_ports="$(ask_ports "UDP ports (optional; empty = none)" empty)"
  fi
  if [[ -z "$tcp_ports" && -z "$udp_ports" ]]; then
    err "At least one TCP or UDP port is required."; return 1
  fi

  local args="-mode ${MODE} -key ${KEY} -tunnel :0 -transport ws -ws-path ${ws_path}"
  [[ -n "$tcp_ports" ]] && args+=" -ports ${tcp_ports}"
  [[ -n "$udp_ports" ]] && args+=" -udp ${udp_ports}"
  [[ "$reverse" == true ]] && args+=" -ws-reverse=true"

  local ws_host ws_port ws_listen ws_cert ws_key_file
  if [[ "$will_dial" == true ]]; then
    ws_host=$(ask "Public hostname to dial (SNI = Host), e.g. myapp-xyz.run.app or api.yourdomain")
    [[ -z "$ws_host" ]] && { err "A host to dial is required."; return 1; }
    ws_port=$(ask "Port" 443)
    args+=" -ws-host ${ws_host} -ws-port ${ws_port}"
  else
    local tls_yn
    echo "Does THIS machine terminate TLS itself, or does something in front of it"
    echo "(your own nginx, a CDN, a load balancer) already terminate TLS before"
    echo "forwarding here?"
    tls_yn=$(ask "Terminate TLS on this machine itself? [y/N]" "n")
    if [[ "$tls_yn" =~ ^[Yy] ]]; then
      ws_cert=$(ask "Path to TLS certificate file")
      ws_key_file=$(ask "Path to TLS private key file")
      args+=" -ws-cert ${ws_cert} -ws-key ${ws_key_file}"
    fi
    ws_listen=$(ask "Local address for the ws listener (nginx/the CDN forwards here)" "127.0.0.1:8081")
    args+=" -ws-listen ${ws_listen}"
  fi

  install_binary || return 1

  mkdir -p "$CONF_DIR"; umask 077
  cat >"$WS_CONF" <<EOF
MODE=${MODE}
TCP_PORTS=${tcp_ports}
UDP_PORTS=${udp_ports}
WS_REVERSE=${reverse}
WS_PATH=${ws_path}
WS_HOST=${ws_host:-}
WS_PORT=${ws_port:-}
WS_LISTEN=${ws_listen:-}
WS_CERT=${ws_cert:-}
WS_KEY=${ws_key_file:-}
EOF
  chmod 600 "$WS_CONF"

  cat >"$WS_UNIT" <<EOF
[Unit]
Description=StackTunnel (ws, standalone)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN} ${args}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  chmod 600 "$WS_UNIT"

  if [[ "$MODE" == "server" && -n "$tcp_ports$udp_ports" ]]; then
    open_firewall "$tcp_ports" "$udp_ports" ""
  fi

  systemctl daemon-reload
  systemctl enable "$WS_SERVICE" >/dev/null 2>&1
  systemctl restart "$WS_SERVICE"
  sleep 2

  if systemctl is-active --quiet "$WS_SERVICE"; then
    ok "${WS_SERVICE} is running on its own, independent of ${SERVICE}."
    info "Point a separate outbound/inbound (e.g. a second x-ui inbound) at its port(s) and switch between them yourself."
  else
    err "${WS_SERVICE} failed to start. Log:"
    journalctl -u "$WS_SERVICE" -n 20 --no-pager
    return 1
  fi
}

do_update() {
  if [[ ! -f "$UNIT" ]]; then err "Service is not installed. Run: sudo bash $0 install"; return 1; fi
  warn "Versions are not compatible with each other: update the inside AND outside servers."
  local before; before="$("$BIN" -version 2>/dev/null || echo unknown)"
  install_binary force || return 1
  systemctl restart "$SERVICE" && ok "Updated: ${before}  ->  $("$BIN" -version 2>/dev/null || echo unknown). Service restarted."
}

do_window() { # do_window N : set -window N in the service and restart
  local n="${1:-}"
  if [[ ! "$n" =~ ^[0-9]+$ ]] || (( n < 256 || n > 65536 )); then
    err "Usage: sudo bash $0 window <KB>   (256 to 65536, e.g. 1024)"; return 1
  fi
  if [[ ! -f "$UNIT" ]]; then err "Service is not installed. Run: sudo bash $0 install"; return 1; fi
  sed -i -E "/^ExecStart=/ { s/ -window [0-9]+//; s/\$/ -window ${n}/ }" "$UNIT"
  if [[ -f "$CONF" ]]; then
    sed -i '/^WINDOW=/d' "$CONF"; echo "WINDOW=${n}" >> "$CONF"
  fi
  systemctl daemon-reload
  systemctl restart "$SERVICE" && ok "Window set to ${n} KB and service restarted. Do the same on the other server."
}

do_tune() {
  echo
  echo "${B}====== Speed test: find the best -window value ======${N}"
  echo "It measures the real path between your two servers with several window sizes"
  echo "and recommends one (takes about a minute). Run it on BOTH servers:"
  echo "first on the INSIDE (Iran) server, then on the OUTSIDE server."
  if [[ ! -x "$BIN" ]]; then err "stacktunnel is not installed yet. Run the install first."; return 1; fi

  local MODE="" KEY="" IRAN_IP="" key port role ip tmp rec
  # shellcheck disable=SC1090
  [[ -f "$CONF" ]] && source "$CONF"
  echo "  1) This is the INSIDE (Iran) server   - waits for the test"
  echo "  2) This is the OUTSIDE server         - runs the test"
  while true; do
    role="$(ask "Choice (1 or 2)")"
    [[ "$role" == 1 || "$role" == 2 ]] && break
    err "Enter 1 or 2"
  done
  key="${KEY:-}"
  [[ -n "$key" ]] || key="$(ask "Shared key")"
  port="$(ask "Port for the test (must be open on the inside server's firewall)" 4100)"
  valid_port "$port" || { err "Invalid port"; return 1; }

  if [[ "$role" == 1 ]]; then
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
      confirm "Open TCP ${port} in ufw for the test?" y && ufw allow "${port}/tcp" >/dev/null && ok "tcp ${port} opened (remove later with: ufw delete allow ${port}/tcp)"
    fi
    info "Waiting for the test. Now run this script's tune option on the OUTSIDE server."
    "$BIN" -mode tune-server -key "$key" -tunnel ":${port}"
  else
    ip="${IRAN_IP%%,*}"; ip="${ip%%:*}"
    ip="$(ask "Inside (Iran) server IP" "$ip")"
    [[ -n "$ip" ]] || { err "IP is required"; return 1; }
    tmp="$(mktemp)"
    "$BIN" -mode tune-client -key "$key" -tunnel "${ip}:${port}" 2>&1 | tee "$tmp"
    rec="$(grep -oE 'Recommended: +-window [0-9]+' "$tmp" | grep -oE '[0-9]+$' | tail -n1)"
    rm -f "$tmp"
    if [[ -n "$rec" ]]; then
      echo
      if [[ -f "$UNIT" ]] && confirm "Apply -window ${rec} to THIS server's service now?" y; then
        do_window "$rec"
      fi
      warn "Also run on the inside server:  sudo bash $0 window ${rec}"
    fi
  fi
}

do_show() {
  [[ -f "$CONF" ]] || { err "No config found."; return 1; }
  cat "$CONF"
}

do_uninstall() {
  confirm "Remove the tunnel completely?" n || return 0
  systemctl stop "$SERVICE" 2>/dev/null
  systemctl disable "$SERVICE" 2>/dev/null
  rm -f "$UNIT" "$BIN"
  rm -rf "$CONF_DIR"
  systemctl daemon-reload
  ok "Removed. (ufw rules you opened were left untouched.)"
}

menu() {
  echo
  echo "${B}StackTunnel${N}"
  echo "  1) Install / reconfigure"
  echo "  2) Status"
  echo "  3) Live log"
  echo "  4) Restart"
  echo "  5) Update binary (download latest release)"
  echo "  6) Speed test / choose window size"
  echo "  7) Show config (includes key)"
  echo "  8) Uninstall"
  echo "  9) Add UDP fallback transport (same service, auto-failover)"
  echo " 10) Add WS/CDN fallback transport (same service, auto-failover)"
  echo " 11) Add a STANDALONE ws service (own port/provider - you switch)"
  echo " 12) Remove a transport from the primary service (back to tcp[,udp])"
  echo " 13) List standalone ws services"
  echo " 14) Remove a standalone ws service"
  echo "  0) Exit"
  case "$(ask "Choice")" in
    1) do_install ;;
    2) do_status ;;
    3) journalctl -u "$SERVICE" -f ;;
    4) systemctl restart "$SERVICE" && ok "Restarted." ;;
    5) do_update ;;
    6) do_tune ;;
    7) do_show ;;
    8) do_uninstall ;;
    9) do_add_transport udp ;;
    10) do_add_transport ws ;;
    11) do_add_ws_service ;;
    12) do_remove_transport "$(ask "Transport to remove (udp or ws)")" ;;
    13) do_list_ws_services ;;
    14) do_remove_ws_service "$(ask "Name of the standalone ws service to remove")" ;;
    *) exit 0 ;;
  esac
}

need_root
case "${1:-}" in
  install)      do_install ;;
  status)       do_status ;;
  logs)         journalctl -u "$SERVICE" -f ;;
  restart)      systemctl restart "$SERVICE" && ok "Restarted." ;;
  update)       do_update ;;
  tune)         do_tune ;;
  window)       do_window "${2:-}" ;;
  show)         do_show ;;
  uninstall)    do_uninstall ;;
  enable-udp)   do_add_transport udp ;;
  enable-ws)    do_add_transport ws ;;
  disable-transport) do_remove_transport "${2:-}" ;;
  add-ws-service)    do_add_ws_service "${2:-}" ;;
  list-ws-services)  do_list_ws_services ;;
  remove-ws-service) do_remove_ws_service "${2:-}" ;;
  "")           menu ;;
  *)            echo "Usage: bash $0 [install|status|logs|restart|update|tune|window N|show|uninstall|enable-udp|enable-ws|disable-transport NAME|add-ws-service [NAME]|list-ws-services|remove-ws-service NAME]" ;;
esac
