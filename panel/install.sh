#!/usr/bin/env bash
# StackTunnel Panel installer
#   sudo bash install.sh agent --name hz1  --role kharej --allow IRAN_IP [--port 9555]
#   sudo bash install.sh agent --name iran --role iran          (Iran server: agent on loopback)
#   sudo bash install.sh panel                                   (Iran server)
#   sudo bash install.sh update      (re-download and restart whatever is installed here)
#   sudo bash install.sh uninstall
# One-link install (downloads everything from GitHub):
#   curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel/install.sh | sudo bash -s -- panel
# Upgrading from the old "mytunnel" panel keeps the agent key, token and the server list.
set -euo pipefail
BASE=${ST_PANEL_BASE:-https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel}
SRC=""
# run from a checkout/copy: use the files next to this script; piped from curl: download them
if [ -f "${BASH_SOURCE[0]:-}" ] && [ "$(basename "${BASH_SOURCE[0]}")" = install.sh ]; then
  SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi
DST=/opt/stacktunnel-panel
ETC=/etc/stacktunnel-panel
OLD=/etc/mytunnel
die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
command -v python3 >/dev/null || die "python3 is required (apt install -y python3)"
command -v openssl >/dev/null || die "openssl is required"

CMD=${1:-}; shift || true
NAME="" ROLE="" PORT=9555 ALLOW="" LISTEN=""
while [ $# -gt 0 ]; do
  case $1 in
    --name) NAME=$2; shift 2 ;;
    --role) ROLE=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    --allow) ALLOW=$2; shift 2 ;;
    --listen) LISTEN=$2; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done

prepare() {
  mkdir -p "$DST" "$ETC/backup"; chmod 700 "$ETC"
  local tmp; tmp=$(mktemp -d)
  for f in st_agent.py st_panel.py panel.html; do
    if [ -n "$SRC" ]; then
      [ -f "$SRC/$f" ] && cp "$SRC/$f" "$tmp/$f"
    else
      curl -fsSL --retry 3 -m 60 "$BASE/$f" -o "$tmp/$f" || { rm -rf "$tmp"; die "download failed: $BASE/$f"; }
    fi
  done
  for f in st_agent.py st_panel.py; do
    [ -f "$tmp/$f" ] && { python3 -m py_compile "$tmp/$f" || { rm -rf "$tmp"; die "$f is broken, nothing installed"; }; }
  done
  for f in st_agent.py st_panel.py panel.html; do
    [ -f "$tmp/$f" ] && install -m 644 "$tmp/$f" "$DST/$f"
  done
  rm -rf "$tmp"
  chmod 755 "$DST"/*.py 2>/dev/null || true
}

unit() { # unit NAME SCRIPT
  cat >/etc/systemd/system/$1.service <<EOF
[Unit]
Description=$1
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 $2
Restart=always
RestartSec=5
Nice=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$1" >/dev/null 2>&1
  systemctl restart "$1"
}

retire_old() { # retire_old agent|panel : stop the old mytunnel-* service of that kind
  if [ -f /etc/systemd/system/mytunnel-$1.service ]; then
    systemctl disable --now mytunnel-$1 >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/mytunnel-$1.service
    systemctl daemon-reload
    echo "removed old mytunnel-$1 service"
  fi
  if [ ! -f /etc/systemd/system/mytunnel-agent.service ] && [ ! -f /etc/systemd/system/mytunnel-panel.service ]; then
    rm -rf /opt/mytunnel /usr/local/bin/mt-panel
  fi
}

fw_rule() { iptables -C "$@" 2>/dev/null || iptables -I "$@"; }

case $CMD in
agent)
  [ -n "$NAME" ] || die "--name is required"
  case $ROLE in iran|kharej) ;; *) die "--role iran|kharej is required" ;; esac
  for t in ss ip ping; do command -v $t >/dev/null || echo "warning: '$t' missing (apt install -y iproute2 iputils-ping)"; done
  prepare
  # keep the identity of an existing agent (old or new layout) so the panel still trusts it
  if [ ! -f $ETC/agent.key ] && [ -f $OLD/agent.key ]; then
    cp -p $OLD/agent.key $OLD/agent.crt $ETC/
    echo "kept the existing agent certificate from $OLD"
  fi
  if [ ! -f $ETC/agent.key ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=$(openssl rand -hex 6)" -keyout $ETC/agent.key -out $ETC/agent.crt 2>/dev/null
  fi
  chmod 600 $ETC/agent.key
  TOKEN=""
  for f in $ETC/agent.json $OLD/agent.json; do
    [ -z "$TOKEN" ] && [ -f $f ] && TOKEN=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["token"])' $f 2>/dev/null || true)
  done
  [ -n "$TOKEN" ] || TOKEN=$(openssl rand -hex 24)
  if [ -z "$LISTEN" ]; then
    if [ "$ROLE" = iran ]; then LISTEN=127.0.0.1:$PORT; else LISTEN=0.0.0.0:$PORT; fi
  fi
  PUB=$(curl -4 -s -m 5 https://api.ipify.org 2>/dev/null || true)
  [ -n "$PUB" ] || PUB=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
  cat >$ETC/agent.json <<EOF
{"name": "$NAME", "role": "$ROLE", "listen": "$LISTEN", "token": "$TOKEN",
 "cert": "$ETC/agent.crt", "key": "$ETC/agent.key", "public_ip": "$PUB"}
EOF
  chmod 600 $ETC/agent.json
  if [ -n "$ALLOW" ]; then
    command -v iptables >/dev/null || die "iptables missing"
    fw_rule INPUT -p tcp --dport "$PORT" -m comment --comment stacktunnel-agent -j DROP
    fw_rule INPUT -p tcp -s "$ALLOW" --dport "$PORT" -m comment --comment stacktunnel-agent -j ACCEPT
    if systemctl is-active --quiet firewalld 2>/dev/null; then  # Oracle Linux / RHEL: firewalld filters separately
      firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$ALLOW/32\" port port=\"$PORT\" protocol=\"tcp\" accept" >/dev/null
      firewall-cmd --reload >/dev/null
      echo "firewalld: port $PORT allowed from $ALLOW"
    fi
    echo "firewall: port $PORT allowed only from $ALLOW"
  elif [ "$ROLE" = kharej ]; then
    echo "warning: no --allow IRAN_IP given, port $PORT is open to everyone (token + TLS still required)"
  fi
  retire_old agent
  unit stacktunnel-agent "$DST/st_agent.py"
  FP=$(openssl x509 -in $ETC/agent.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f)
  HOST=$PUB; [ "$ROLE" = iran ] && HOST=127.0.0.1
  echo
  echo "agent '$NAME' is running on $LISTEN"
  echo "add it in the panel (Servers tab) with:"
  echo "  address: $HOST   port: $PORT   public IP: $PUB"
  echo "  token:   $TOKEN"
  echo "  fingerprint: $FP"
  ;;
panel)
  prepare
  if [ ! -f $ETC/panel.json ]; then
    if [ -f $OLD/panel.json ]; then
      cp -p $OLD/panel.json $ETC/panel.json
      echo "kept the server list from the old panel"
    else
      cat >$ETC/panel.json <<EOF
{"listen": "${LISTEN:-127.0.0.1:8480}", "interval": 15, "password": "",
 "urls": ["https://www.google.com", "https://www.arvancloud.ir"], "nodes": []}
EOF
    fi
  fi
  chmod 600 $ETC/panel.json
  ln -sf $DST/st_panel.py /usr/local/bin/stacktunnel-panel
  retire_old panel
  unit stacktunnel-panel "$DST/st_panel.py"
  echo
  echo "StackTunnel Panel is running on $(python3 -c 'import json;print(json.load(open("/etc/stacktunnel-panel/panel.json"))["listen"])')"
  echo "open it from your PC:  ssh -L 8480:127.0.0.1:8480 root@THIS_SERVER   then http://127.0.0.1:8480"
  ;;
update)
  [ -d "$DST" ] || die "nothing installed in $DST"
  prepare
  for s in stacktunnel-agent stacktunnel-panel; do
    systemctl is-enabled --quiet $s 2>/dev/null && systemctl restart $s && echo "restarted $s"
  done
  [ -f $DST/st_panel.py ] && ln -sf $DST/st_panel.py /usr/local/bin/stacktunnel-panel
  echo "updated: $(grep -m1 '^VERSION' $DST/st_agent.py)"
  ;;
uninstall)
  for s in stacktunnel-agent stacktunnel-panel; do
    systemctl disable --now $s >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/$s.service
  done
  systemctl daemon-reload
  if command -v iptables >/dev/null; then
    while iptables -S INPUT 2>/dev/null | grep -q stacktunnel-agent; do
      iptables -S INPUT | grep stacktunnel-agent | head -1 | sed 's/^-A/-D/' | xargs iptables
    done
  fi
  rm -rf "$DST" /usr/local/bin/stacktunnel-panel
  echo "removed (keys, config and unit backups kept in $ETC)"
  ;;
*) echo "usage: install.sh agent|panel|update|uninstall ..."; exit 1 ;;
esac
