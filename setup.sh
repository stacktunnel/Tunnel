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
IRAN_IP=${iran_ip:-}
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
    *) exit 0 ;;
  esac
}

need_root
case "${1:-}" in
  install)   do_install ;;
  status)    do_status ;;
  logs)      journalctl -u "$SERVICE" -f ;;
  restart)   systemctl restart "$SERVICE" && ok "Restarted." ;;
  update)    do_update ;;
  tune)      do_tune ;;
  window)    do_window "${2:-}" ;;
  show)      do_show ;;
  uninstall) do_uninstall ;;
  "")        menu ;;
  *)         echo "Usage: bash $0 [install|status|logs|restart|update|tune|window N|show|uninstall]" ;;
esac
