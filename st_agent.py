#!/usr/bin/env python3
"""StackTunnel Panel agent: runs on every server (Iran and abroad).

- reports services, tunnel units, ports, connections and reachability probes
- manages stacktunnel systemd units (validated flags only, backup + automatic rollback)
- serves speed tests (direct, and through the tunnel)

Talks only to the panel, over TLS with a bearer token. Python 3 standard library only.
"""
import difflib
import hmac
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.3.1"
CONF_PATH = os.environ.get("ST_AGENT_CONF", "/etc/stacktunnel-panel/agent.json")
UNIT_DIR = os.environ.get("ST_UNIT_DIR", "/etc/systemd/system")
BACKUP_DIR = os.environ.get("ST_BACKUP_DIR", "/etc/stacktunnel-panel/backup")
SYSTEMCTL = os.environ.get("ST_SYSTEMCTL", "systemctl")
JOURNALCTL = os.environ.get("ST_JOURNALCTL", "journalctl")
ST_BIN = os.environ.get("ST_BIN", "/usr/local/bin/stacktunnel")
VERIFY_WAIT = float(os.environ.get("ST_VERIFY_WAIT", "4"))

SERVICE_RE = re.compile(
    r"(xray|x-ui|3x-ui|sing-box|singbox|v2ray|hysteria|tuic|backhaul|rathole|frp|gost|"
    r"paqet|wg-quick|wireguard|openvpn|ocserv|nginx|caddy|haproxy|marzban|hiddify|"
    r"shadowsocks|ss-server|trojan|naive|tunnel|udp2raw|kcptun|warp|cloudflared)",
    re.I,
)
TUN_KINDS = {"gre", "gretap", "ipip", "sit", "wireguard", "vxlan", "tun", "ip6tnl", "ip6gre", "geneve"}


def run(cmd, timeout=6):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except Exception:
        return ""


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


# ---------- system facts ----------

def sys_info():
    up = read("/proc/uptime").split()
    load = read("/proc/loadavg").split()
    mem = {}
    for line in read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        if k in ("MemTotal", "MemAvailable"):
            mem[k] = int(v.split()[0]) * 1024
    os_name = ""
    for line in read("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            os_name = line.split("=", 1)[1].strip('"')
    return {
        "hostname": socket.gethostname(),
        "os": os_name,
        "uptime_s": int(float(up[0])) if up else None,
        "load": [float(x) for x in load[:3]] if load else [],
        "cpus": os.cpu_count(),
        "mem_total": mem.get("MemTotal"),
        "mem_avail": mem.get("MemAvailable"),
    }


def interfaces():
    """Addresses + tunnel-type links + byte counters."""
    addrs, tunnels = [], []
    try:
        for it in json.loads(run(["ip", "-j", "-d", "addr"]) or "[]"):
            name = it.get("ifname")
            kind = (it.get("linkinfo") or {}).get("info_kind", "")
            ips = [a["local"] for a in it.get("addr_info", []) if a.get("scope") == "global"]
            for ip in ips:
                addrs.append({"if": name, "ip": ip})
            if kind in TUN_KINDS or name.startswith(("wg", "tun", "gre", "ipip", "sit", "6to4", "vxlan")):
                if name in ("sit0", "gre0", "gretap0", "erspan0", "ip_vti0", "ip6tnl0", "tunl0", "ip6gre0", "ip6_vti0"):
                    continue
                d = (it.get("linkinfo") or {}).get("info_data", {}) or {}
                tunnels.append({
                    "if": name, "kind": kind or "?", "state": it.get("operstate"),
                    "ips": ips, "local": d.get("local"), "remote": d.get("remote"),
                })
    except Exception:
        pass
    counters = {}
    for line in read("/proc/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        f = rest.split()
        if len(f) >= 9:
            counters[name.strip()] = {"rx": int(f[0]), "tx": int(f[8])}
    for t in tunnels:
        t.update(counters.get(t["if"], {}))
    return addrs, tunnels, counters


def wireguard_peers():
    out = run(["wg", "show", "all", "dump"])
    peers = []
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) == 9:  # peer line
            peers.append({"if": f[0], "endpoint": f[3], "handshake": int(f[5] or 0),
                          "rx": int(f[6] or 0), "tx": int(f[7] or 0)})
    return peers


def services():
    out = run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"])
    res = []
    for line in out.splitlines():
        f = line.split(None, 4)
        if len(f) < 4 or not SERVICE_RE.search(f[0]):
            continue
        if f[2] == "inactive" and f[1] != "loaded":
            continue
        res.append({"unit": f[0], "load": f[1], "active": f[2], "sub": f[3]})
    # docker containers (marzban etc.)
    dk = run(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}"], timeout=4)
    for line in dk.splitlines():
        f = line.split("\t")
        if len(f) == 3:
            res.append({"unit": "docker:" + f[0], "load": f[1], "active": "active" if f[2].startswith("Up") else "failed", "sub": f[2]})
    return res


def split_addr(a):
    a = a.strip()
    if a.startswith("["):
        host, _, port = a[1:].rpartition("]:")
    else:
        host, _, port = a.rpartition(":")
    host = host.split("%")[0]
    if host.startswith("::ffff:"):
        host = host[7:]
    return host, port


PROC_RE = re.compile(r'\("([^"]+)"')


def sockets():
    out = run(["ss", "-Htunap"])
    listen, estab = [], {}
    for line in out.splitlines():
        f = line.split()
        if len(f) < 6:
            continue
        proto, state, local, peer = f[0], f[1], f[4], f[5]
        proc = PROC_RE.search(line)
        proc = proc.group(1) if proc else "?"
        lh, lp = split_addr(local)
        ph, pp = split_addr(peer)
        if state == "LISTEN" or (proto == "udp" and state == "UNCONN" and pp == "*"):
            if lh.startswith("127.") or lh == "::1":
                continue
            listen.append({"proto": proto, "addr": lh, "port": int(lp) if lp.isdigit() else lp, "proc": proc})
        elif state == "ESTAB":
            if ph.startswith("127.") or ph == "::1" or lh.startswith("127."):
                continue
            key = (proto, lp, ph, pp, proc)
            estab[key] = estab.get(key, 0) + 1
    # dedupe listen
    seen, lst = set(), []
    for x in listen:
        k = (x["proto"], x["port"], x["proc"])
        if k not in seen:
            seen.add(k)
            lst.append(x)
    est = [{"proto": k[0], "lport": int(k[1]) if k[1].isdigit() else k[1], "peer": k[2],
            "pport": int(k[3]) if k[3].isdigit() else k[3], "proc": k[4], "n": n}
           for k, n in estab.items()]
    return lst, est


# ---------- probes (requested by panel) ----------

HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")
_probe_lock = threading.Lock()
_probe_state = {"ts": 0, "targets": [], "urls": [], "results": [], "running": False}


def ping(host):
    out = run(["ping", "-c", "3", "-i", "0.3", "-W", "2", "-q", host], timeout=8)
    m = re.search(r"(\d+)% packet loss", out)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", out)
    if not m:
        return None, None
    return 100 - int(m.group(1)), float(rtt.group(1)) if rtt else None


def tcp(host, port):
    t = time.time()
    try:
        with socket.create_connection((host, port), timeout=4):
            return round((time.time() - t) * 1000, 1)
    except Exception:
        return None


def https(url):
    import urllib.request
    t = time.time()
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return {"ok": True, "code": r.status, "ms": round((time.time() - t) * 1000)}
    except Exception as e:
        code = getattr(e, "code", None)
        if code:  # got an HTTP answer -> reachable
            return {"ok": True, "code": code, "ms": round((time.time() - t) * 1000)}
        return {"ok": False, "err": type(e).__name__}


def do_probes(targets, urls):
    def one(t):
        loss_ok, rtt = ping(t["host"])
        ports = {}
        for p in t.get("ports", []):
            ports[str(p)] = tcp(t["host"], p)
        return {"host": t["host"], "name": t.get("name"), "ping_ok": loss_ok, "ping_ms": rtt, "tcp": ports}

    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(one, targets))
        url_res = dict(zip(urls, ex.map(https, urls)))
    with _probe_lock:
        _probe_state.update(ts=int(time.time()), results=res, url_results=url_res, running=False)


def probes(targets, urls):
    clean = []
    for t in (targets or [])[:20]:
        h = str(t.get("host", ""))
        if not HOST_RE.match(h):
            continue
        ports = [int(p) for p in t.get("ports", [])[:5] if str(p).isdigit() and 0 < int(p) < 65536]
        clean.append({"host": h, "name": str(t.get("name", ""))[:40], "ports": ports})
    urls = [u for u in (urls or [])[:6] if isinstance(u, str) and re.match(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/\S*)?$", u)]
    with _probe_lock:
        stale = time.time() - _probe_state["ts"] > 20 or _probe_state["targets"] != clean or _probe_state["urls"] != urls
        if stale and not _probe_state["running"]:
            _probe_state.update(running=True, targets=clean, urls=urls)
            threading.Thread(target=do_probes, args=(clean, urls), daemon=True).start()
        return {"ts": _probe_state["ts"], "results": _probe_state["results"], "urls": _probe_state.get("url_results", {})}



# ---------- stacktunnel units ----------

UNIT_NAME_RE = re.compile(r"^stacktunnel(-[a-z0-9]+){0,4}$")
RESERVED = {"stacktunnel-panel", "stacktunnel-agent"}
DUR = r"(0|(\d+(\.\d+)?(ns|us|ms|s|m|h))+)"
HOSTPORT = r"([A-Za-z0-9.\-]*|\[[0-9a-fA-F:]+\]):\d{1,5}"
IPV4 = r"(\d{1,3}\.){3}\d{1,3}"

# flag -> (kind, check). Only these flags can ever be written into a unit.
FLAGS = {
    "mode": ("enum", {"server", "client"}),
    "key": ("re", r"[A-Za-z0-9_\-]{8,128}"),
    "tunnel": ("re", HOSTPORT),
    "transport": ("csvenum", {"tcp", "udp", "ws"}),
    "ports": ("ports", None),
    "udp": ("ports", None),
    "pad": ("int", (0, 4096)),
    "conns": ("int", (1, 64)),
    "rotate": ("re", DUR),
    "retire-timeout": ("re", DUR),
    "source-ips": ("re", rf"{IPV4}(,{IPV4})*"),
    "bind": ("re", r"[0-9a-fA-F.:]{2,45}"),
    "fec-data": ("int", (1, 64)),
    "fec-parity": ("int", (0, 32)),
    "fragment": ("bool", None),
    "junk": ("re", DUR),
    "window": ("int", (16, 65536)),
    "windows": ("re", r"\d{2,5}(,\d{2,5}){0,9}"),
    "ws-cert": ("re", r"/[A-Za-z0-9_./\-]{1,200}"),
    "ws-key": ("re", r"/[A-Za-z0-9_./\-]{1,200}"),
    "ws-host": ("re", r"[A-Za-z0-9.\-]{1,253}"),
    "ws-listen": ("re", HOSTPORT),
    "ws-path": ("re", r"/[A-Za-z0-9_./\-]{0,100}"),
    "ws-port": ("int", (1, 65535)),
    "ws-reverse": ("bool", None),
    "ws-tls": ("bool", None),
}
BOOL_FLAGS = {k for k, v in FLAGS.items() if v[0] == "bool"}


def check_flag(flag, value):
    if flag not in FLAGS:
        return f"unknown flag -{flag}"
    kind, rule = FLAGS[flag]
    v = str(value).strip()
    if kind == "enum" and v not in rule:
        return f"-{flag}: must be one of {sorted(rule)}"
    if kind == "csvenum" and (not v or any(x not in rule for x in v.split(","))):
        return f"-{flag}: comma list of {sorted(rule)}"
    if kind == "int":
        if not re.fullmatch(r"\d+", v) or not rule[0] <= int(v) <= rule[1]:
            return f"-{flag}: integer {rule[0]}..{rule[1]}"
    if kind == "bool" and v not in ("true", "false"):
        return f"-{flag}: true/false"
    if kind == "ports":
        if v and not all(re.fullmatch(r"\d{1,5}", p) and 0 < int(p) < 65536 for p in v.split(",")):
            return f"-{flag}: comma list of ports"
    if kind == "re" and not re.fullmatch(rule, v):
        return f"-{flag}: invalid value"
    return None


def parse_exec(line):
    """ExecStart value -> (binary, [[flag, value], ...])"""
    toks = shlex.split(line)
    if not toks:
        return None, []
    binary, args, i = toks[0], [], 1
    while i < len(toks):
        t = toks[i]
        if not t.startswith("-"):
            args.append(["_", t]); i += 1; continue
        name = t.lstrip("-")
        if "=" in name:
            name, val = name.split("=", 1)
            i += 1
        elif name in BOOL_FLAGS:
            val = "true"; i += 1
        elif i + 1 < len(toks):
            val = toks[i + 1]; i += 2
        else:
            val = ""; i += 1
        args.append([name, val])
    return binary, args


def parse_unit(text):
    desc, execs = "", ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Description="):
            desc = s.split("=", 1)[1]
        elif s.startswith("ExecStart="):
            execs = s.split("=", 1)[1]
    binary, args = parse_exec(execs)
    return {"description": desc, "binary": binary, "args": args, "exec": execs}


def build_unit(desc, args):
    parts = [ST_BIN]
    for flag, val in args:
        parts.append(f"-{flag}={val}" if flag in BOOL_FLAGS else f"-{flag}")
        if flag not in BOOL_FLAGS:
            parts.append(shlex.quote(str(val)))
    desc = re.sub(r"[\r\n]", " ", desc or "StackTunnel")[:120]
    return (f"[Unit]\nDescription={desc}\nAfter=network-online.target\nWants=network-online.target\n\n"
            f"[Service]\nType=simple\nExecStart={' '.join(parts)}\nRestart=always\nRestartSec=3\n"
            f"LimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n")


def unit_path(name):
    return os.path.join(UNIT_DIR, name + ".service")


def check_name(name):
    if not isinstance(name, str) or not UNIT_NAME_RE.fullmatch(name) or name in RESERVED:
        raise ValueError("unit name must look like stacktunnel or stacktunnel-xyz")


def sctl(*a, timeout=20):
    p = subprocess.run([SYSTEMCTL, *a], capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def unit_state(name):
    _, out = sctl("show", name, "-p", "ActiveState", "-p", "SubState", "-p", "NRestarts",
                  "-p", "UnitFileState", "-p", "ActiveEnterTimestamp")
    st = {}
    for line in out.splitlines():
        k, _, v = line.partition("=")
        st[k] = v
    return st


def logs(name, n=60):
    try:
        p = subprocess.run([JOURNALCTL, "-u", name, "-n", str(int(n)), "--no-pager", "-o", "short-iso"],
                           capture_output=True, text=True, timeout=10)
        return p.stdout[-20000:]
    except Exception as e:
        return str(e)


_bin_version = None


def st_version():
    global _bin_version
    if _bin_version is None:
        _bin_version = run([ST_BIN, "-version"]).strip() or "?"
    return _bin_version


def list_units():
    res = []
    try:
        names = sorted(f[:-8] for f in os.listdir(UNIT_DIR) if f.endswith(".service"))
    except Exception:
        names = []
    for name in names:
        if not UNIT_NAME_RE.fullmatch(name) or name in RESERVED:
            continue
        u = parse_unit(read(unit_path(name)))
        u["name"] = name
        u["state"] = unit_state(name)
        res.append(u)
    return res


_unit_lock = threading.Lock()


def validate_args(args):
    if not isinstance(args, list) or not args:
        raise ValueError("args required")
    clean, seen, errs = [], set(), []
    for item in args:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValueError("args must be [[flag, value], ...]")
        flag, val = str(item[0]).lstrip("-"), str(item[1]).strip()
        if flag in seen:
            errs.append(f"-{flag} given twice"); continue
        seen.add(flag)
        if flag in ("ports", "udp") and val == "":
            continue  # empty port list: drop the flag
        e = check_flag(flag, val)
        if e:
            errs.append(e)
        clean.append([flag, val])
    for need in ("mode", "key", "tunnel"):
        if need not in seen:
            errs.append(f"-{need} is required")
    if errs:
        raise ValueError("; ".join(errs))
    return clean


def apply_unit(name, desc, args, dry=False):
    check_name(name)
    args = validate_args(args)
    new = build_unit(desc, args)
    path = unit_path(name)
    old = read(path) if os.path.exists(path) else None
    diff = "".join(difflib.unified_diff((old or "").splitlines(True), new.splitlines(True),
                                        f"{name}.service (now)", f"{name}.service (new)"))
    if dry:
        return {"ok": True, "dry": True, "diff": diff, "changed": old != new, "exists": old is not None}
    if old == new:
        return {"ok": True, "changed": False, "diff": ""}
    with _unit_lock:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        backup = None
        if old is not None:
            backup = os.path.join(BACKUP_DIR, f"{name}.{time.strftime('%Y%m%d-%H%M%S')}.service")
            shutil.copy2(path, backup)
        tmp = path + ".st-tmp"
        with open(tmp, "w") as f:
            f.write(new)
        os.chmod(tmp, 0o600)  # units hold the tunnel key
        os.replace(tmp, path)
        sctl("daemon-reload")
        sctl("enable", name)
        sctl("restart", name)
        time.sleep(0.5)
        r0 = unit_state(name).get("NRestarts", "0")
        time.sleep(VERIFY_WAIT)
        st = unit_state(name)
        healthy = st.get("ActiveState") == "active" and st.get("NRestarts", "0") == r0
        if healthy:
            return {"ok": True, "changed": True, "diff": diff, "backup": backup, "state": st}
        # roll back
        log = logs(name, 40)
        if old is not None:
            with open(tmp, "w") as f:
                f.write(old)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            sctl("daemon-reload")
            sctl("restart", name)
        else:
            sctl("disable", "--now", name)
            os.remove(path)
            sctl("daemon-reload")
        return {"ok": False, "rolled_back": True, "error": "service did not stay up; previous version restored",
                "logs": log, "diff": diff}


def unit_action(name, action):
    check_name(name)
    if action not in ("start", "stop", "restart", "enable", "disable"):
        raise ValueError("bad action")
    if not os.path.exists(unit_path(name)):
        raise ValueError("no such unit")
    code, out = sctl(action, name)
    time.sleep(1.5)
    return {"ok": code == 0, "out": out, "state": unit_state(name)}


def delete_unit(name):
    check_name(name)
    path = unit_path(name)
    if not os.path.exists(path):
        raise ValueError("no such unit")
    with _unit_lock:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        backup = os.path.join(BACKUP_DIR, f"{name}.{time.strftime('%Y%m%d-%H%M%S')}.deleted.service")
        shutil.copy2(path, backup)
        sctl("disable", "--now", name)
        os.remove(path)
        sctl("daemon-reload")
    return {"ok": True, "backup": backup}


def list_backups(name):
    check_name(name)
    try:
        return sorted((f for f in os.listdir(BACKUP_DIR) if f.startswith(name + ".")), reverse=True)[:20]
    except Exception:
        return []


def restore_backup(name, fname):
    check_name(name)
    if fname not in list_backups(name):
        raise ValueError("no such backup")
    u = parse_unit(read(os.path.join(BACKUP_DIR, fname)))
    args = [a for a in u["args"] if a[0] != "_"]
    return apply_unit(name, u["description"], args)


# ---------- speed test helpers ----------

CHUNK = os.urandom(65536)
MAX_BYTES = 200 * 1024 * 1024
_listeners = {}


def speed_listen(port, seconds):
    """Temporary plain TCP server on 127.0.0.1:port. Client sends 'N\\n', gets N random bytes."""
    port, seconds = int(port), max(5, min(int(seconds), 180))
    if not 0 < port < 65536:
        raise ValueError("bad port")
    if port in _listeners:
        return {"ok": True, "port": port, "already": True}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError as e:
        s.close()
        raise ValueError(f"port {port} is busy on this server ({e.strerror}); pick a tunnel port with nothing behind it")
    s.listen(16)
    s.settimeout(1)
    _listeners[port] = s
    deadline = time.time() + seconds

    def serve(c):
        try:
            c.settimeout(30)
            buf = b""
            while b"\n" not in buf and len(buf) < 32:
                d = c.recv(32)
                if not d:
                    return
                buf += d
            n = min(int(buf.split(b"\n")[0] or 0), MAX_BYTES)
            while n > 0:
                k = min(n, len(CHUNK))
                c.sendall(CHUNK[:k])
                n -= k
        except Exception:
            pass
        finally:
            c.close()

    def loop():
        try:
            while time.time() < deadline:
                try:
                    c, _ = s.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=serve, args=(c,), daemon=True).start()
        finally:
            s.close()
            _listeners.pop(port, None)

    threading.Thread(target=loop, daemon=True).start()
    return {"ok": True, "port": port, "seconds": seconds}

# ---------- HTTP ----------

CONF = {}


def status(body):
    addrs, tunnels, counters = interfaces()
    listen, estab = sockets()
    return {
        "agent": VERSION,
        "name": CONF.get("name"),
        "role": CONF.get("role"),
        "time": int(time.time()),
        "sys": sys_info(),
        "addrs": addrs,
        "tunnels": tunnels,
        "wg_peers": wireguard_peers(),
        "services": services(),
        "listen": listen,
        "estab": estab,
        "units": list_units(),
        "st_version": st_version(),
        "probes": probes(body.get("targets"), body.get("urls")),
        "public_ip": CONF.get("public_ip"),
    }


def route(path, body):
    if path == "/status":
        return status(body)
    if path == "/unit/get":
        check_name(body.get("name"))
        p = unit_path(body["name"])
        if not os.path.exists(p):
            raise ValueError("no such unit")
        u = parse_unit(read(p))
        u.update(name=body["name"], state=unit_state(body["name"]), backups=list_backups(body["name"]))
        return u
    if path == "/unit/apply":
        return apply_unit(body.get("name"), body.get("description", ""), body.get("args"), bool(body.get("dry")))
    if path == "/unit/action":
        return unit_action(body.get("name"), body.get("action"))
    if path == "/unit/delete":
        return delete_unit(body.get("name"))
    if path == "/unit/logs":
        check_name(body.get("name"))
        return {"logs": logs(body["name"], min(int(body.get("n", 80)), 500))}
    if path == "/unit/restore":
        return restore_backup(body.get("name"), body.get("backup"))
    if path == "/speed/listen":
        return speed_listen(body.get("port"), body.get("seconds", 60))
    raise LookupError(path)


class H(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""
    timeout = 30
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, data, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        tok = self.headers.get("Authorization", "")
        return hmac.compare_digest(tok.encode(), ("Bearer " + CONF["token"]).encode())

    def do_GET(self):
        self.close_connection = True
        if not self._authed():
            return self._send(404, b"")
        m = re.fullmatch(r"/speed/down/(\d+)", self.path)
        if not m:
            return self._send(404, b"")
        n = min(int(m.group(1)), MAX_BYTES)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(n))
        self.end_headers()
        try:
            while n > 0:
                k = min(n, len(CHUNK))
                self.wfile.write(CHUNK[:k])
                n -= k
        except Exception:
            pass

    def do_POST(self):
        self.close_connection = True
        if not self._authed():
            return self._send(404, b"")
        n = int(self.headers.get("Content-Length") or 0)
        if self.path == "/speed/up":
            t, got = time.time(), 0
            n = min(n, MAX_BYTES)
            while got < n:
                d = self.rfile.read(min(65536, n - got))
                if not d:
                    break
                got += len(d)
            return self._send(200, json.dumps({"bytes": got, "ms": round((time.time() - t) * 1000)}).encode())
        try:
            body = json.loads(self.rfile.read(min(n, 1 << 20)) or b"{}")
        except Exception:
            body = {}
        try:
            res, code = route(self.path, body), 200
        except LookupError:
            return self._send(404, b"")
        except ValueError as e:
            res, code = {"ok": False, "error": str(e)}, 400
        except Exception as e:
            res, code = {"ok": False, "error": f"{type(e).__name__}: {e}"}, 500
        self._send(code, json.dumps(res).encode())


def main():
    global CONF
    CONF = json.load(open(CONF_PATH))
    if "--once" in sys.argv:
        print(json.dumps(status({}), indent=1))
        return
    host, _, port = CONF.get("listen", "0.0.0.0:9555").rpartition(":")
    srv = ThreadingHTTPServer((host, int(port)), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CONF["cert"], CONF["key"])
    # handshake happens in the handler thread, so one slow client can't block accept()
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    print(f"stacktunnel-panel agent {VERSION} on {host}:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
