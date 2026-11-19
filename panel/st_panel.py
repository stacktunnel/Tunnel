#!/usr/bin/env python3
"""StackTunnel Panel: runs on the Iran server.

Polls every agent and gives one web UI to see and manage all servers:
status, what connects to what, stacktunnel units (ports, settings,
start/stop, logs, backups), new tunnels, and speed tests.
Python 3 standard library only.

  st_panel.py                 run the web panel
  st_panel.py add-node ...    add/replace a server from the shell
  st_panel.py del-node NAME
  st_panel.py list
"""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.3.1"
CONF_PATH = os.environ.get("ST_PANEL_CONF", "/etc/stacktunnel-panel/panel.json")
DEFAULT_CONF = {
    "listen": "127.0.0.1:8480",
    "interval": 15,
    "password": "",
    "urls": ["https://www.google.com", "https://www.arvancloud.ir"],
    "sni": "www.speedtest.net",
    "nodes": [],
}

STATE = {"nodes": {}, "updated": 0}
LOCK = threading.Lock()
CONF_LOCK = threading.Lock()
SPEED_HISTORY = []
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")


def load_conf():
    c = dict(DEFAULT_CONF)
    if os.path.exists(CONF_PATH):
        c.update(json.load(open(CONF_PATH)))
    return c


def save_conf(c):
    os.makedirs(os.path.dirname(CONF_PATH), exist_ok=True)
    tmp = CONF_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF_PATH)


def node_ip(n):
    return n.get("ip") or n["host"]


def get_node(name):
    for n in load_conf()["nodes"]:
        if n["name"] == name:
            return n
    raise ValueError(f"unknown server {name}")


# ---------- talking to agents ----------

def _conn(node, timeout):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the certificate fingerprint is pinned below instead
    # send a normal-looking SNI: bare-IP TLS on odd ports gets reset by DPI on some routes
    sni = node.get("sni") or load_conf().get("sni") or None
    raw = socket.create_connection((node["host"], int(node.get("port", 9555))), timeout=timeout)
    try:
        s = ctx.wrap_socket(raw, server_hostname=sni)
    except Exception:
        raw.close()
        raise
    c = http.client.HTTPSConnection(node["host"], int(node.get("port", 9555)), timeout=timeout, context=ctx)
    c.sock = s
    fp = hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()
    if not hmac.compare_digest(fp, node["fp"].replace(":", "").lower()):
        c.close()
        raise RuntimeError("certificate fingerprint mismatch (agent reinstalled, or someone in the middle)")
    return c


def agent_call(node, path, body=None, timeout=20):
    c = _conn(node, timeout)
    try:
        c.request("POST", path, json.dumps(body or {}).encode(),
                  {"Authorization": "Bearer " + node["token"], "Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
        if r.status == 404:
            raise RuntimeError("agent refused (wrong token or old agent version)")
        out = json.loads(data or b"{}")
        if r.status != 200:
            raise ValueError(out.get("error") or f"HTTP {r.status}")
        return out
    finally:
        c.close()


def fetch(node, conf):
    targets = []
    for o in conf["nodes"]:
        if o["name"] == node["name"]:
            continue
        ports = list(o.get("probe_ports", [443]))
        if o.get("role") != "iran":  # the Iran agent listens on loopback only
            ports.append(int(o.get("port", 9555)))
        targets.append({"name": o["name"], "host": node_ip(o), "ports": list(dict.fromkeys(ports))})
    t = time.time()
    data = agent_call(node, "/status", {"targets": targets, "urls": conf.get("urls", [])}, timeout=15)
    data["_rtt_ms"] = round((time.time() - t) * 1000)
    return data


def poll_once():
    conf = load_conf()

    def one(n):
        try:
            return n["name"], {"ok": True, "data": fetch(n, conf), "ts": int(time.time())}
        except Exception as e:
            return n["name"], {"ok": False, "err": f"{type(e).__name__}: {e}"[:200], "ts": int(time.time())}

    with ThreadPoolExecutor(8) as ex:
        res = dict(ex.map(one, conf["nodes"]))
    with LOCK:
        for name, r in res.items():
            prev = STATE["nodes"].get(name, {})
            if r["ok"]:
                r["last_ok"] = r["ts"]
            else:
                r["last_ok"] = prev.get("last_ok")
                r["stale"] = prev.get("data") or prev.get("stale")
            STATE["nodes"][name] = r
        for name in list(STATE["nodes"]):
            if name not in res:
                del STATE["nodes"][name]
        STATE["updated"] = int(time.time())


def poll_node(name):
    """Refresh one server right after a change."""
    conf = load_conf()
    n = get_node(name)
    try:
        r = {"ok": True, "data": fetch(n, conf), "ts": int(time.time())}
        r["last_ok"] = r["ts"]
        with LOCK:
            STATE["nodes"][name] = r
    except Exception:
        pass


def poller():
    while True:
        try:
            poll_once()
        except Exception as e:
            print("poll error:", e, file=sys.stderr, flush=True)
        time.sleep(max(5, int(load_conf().get("interval", 15))))


# ---------- analysis ----------

def analyse():
    conf = load_conf()
    with LOCK:
        nodes = json.loads(json.dumps(STATE["nodes"]))
    meta = {n["name"]: n for n in conf["nodes"]}
    ipmap = {}
    for n in conf["nodes"]:
        ipmap[node_ip(n)] = n["name"]
        ipmap.setdefault(n["host"], n["name"])
    for name, r in nodes.items():
        d = r.get("data") or r.get("stale") or {}
        for a in d.get("addrs", []):
            ipmap.setdefault(a["ip"], name)

    agent_ports = {int(n.get("port", 9555)) for n in conf["nodes"]}
    edges, ext_in, ext_out = {}, {}, {}

    def add_edge(cli, srv, proto, port, cproc=None, sproc=None, n=1, kind="conn"):
        k = (cli, srv, proto, str(port), kind)
        e = edges.setdefault(k, {"from": cli, "to": srv, "proto": proto, "port": port, "kind": kind,
                                 "n": 0, "cproc": None, "sproc": None})
        e["n"] = max(e["n"], n) if kind != "conn" else e["n"] + n
        e["cproc"] = e["cproc"] or cproc
        e["sproc"] = e["sproc"] or sproc

    seen_pairs = set()
    for name, r in nodes.items():
        d = r.get("data")
        if not d:
            continue
        listening = {(l["proto"], l["port"]): l["proc"] for l in d.get("listen", [])}
        for e in d.get("estab", []):
            if e["lport"] in agent_ports or e["pport"] in agent_ports:
                continue  # the panel's own polling traffic
            other = ipmap.get(e["peer"])
            inbound = (e["proto"], e["lport"]) in listening
            if other and other != name:
                if inbound:
                    pair = (other, name, e["proto"], e["lport"], e["pport"])
                    if pair in seen_pairs:
                        k = (other, name, e["proto"], str(e["lport"]), "conn")
                        if k in edges:
                            edges[k]["sproc"] = edges[k]["sproc"] or e["proc"]
                        continue
                    seen_pairs.add(pair)
                    add_edge(other, name, e["proto"], e["lport"], None, e["proc"], e["n"])
                else:
                    pair = (name, other, e["proto"], e["pport"], e["lport"])
                    if pair in seen_pairs:
                        k = (name, other, e["proto"], str(e["pport"]), "conn")
                        if k in edges:
                            edges[k]["cproc"] = edges[k]["cproc"] or e["proc"]
                        continue
                    seen_pairs.add(pair)
                    add_edge(name, other, e["proto"], e["pport"], e["proc"], None, e["n"])
            elif not other:
                if inbound:
                    k = (name, e["proto"], e["lport"])
                    x = ext_in.setdefault(k, {"node": name, "proto": e["proto"], "port": e["lport"], "proc": e["proc"], "ips": set(), "n": 0})
                    x["ips"].add(e["peer"])
                    x["n"] += e["n"]
                else:
                    k = (name, e["proc"], e["peer"], e["pport"])
                    x = ext_out.setdefault(k, {"node": name, "proc": e["proc"], "peer": e["peer"], "port": e["pport"], "n": 0})
                    x["n"] += e["n"]
        for t in d.get("tunnels", []):
            other = ipmap.get(t.get("remote") or "")
            if other and other != name:
                a, b = sorted([name, other])
                add_edge(a, b, t["kind"], t["if"], kind="tunnel", n=1)
        for p in d.get("wg_peers", []):
            host = (p.get("endpoint") or "").rpartition(":")[0].strip("[]")
            other = ipmap.get(host)
            if other and other != name:
                a, b = sorted([name, other])
                alive = time.time() - p.get("handshake", 0) < 180
                add_edge(a, b, "wg", p["if"], kind="tunnel" if alive else "tunnel-dead", n=1)

    # fill the "server process" side of edges from the server's listen table
    for e in edges.values():
        d = (nodes.get(e["to"]) or {}).get("data") or {}
        for l in d.get("listen", []):
            if str(l["port"]) == str(e["port"]) and l["proto"] == e["proto"]:
                e["sproc"] = e["sproc"] or l["proc"]

    # reachability matrix: matrix[src][dst] = {...}
    matrix = {}
    for name, r in nodes.items():
        d = r.get("data") or {}
        for pr in (d.get("probes") or {}).get("results", []):
            matrix.setdefault(name, {})[pr.get("name") or pr["host"]] = pr

    return {
        "version": VERSION,
        "updated": STATE["updated"],
        "nodes": [dict(meta.get(n, {"name": n}), **{k: v for k, v in nodes.get(n, {}).items()},
                       token=None) for n in [x["name"] for x in conf["nodes"]]],
        "edges": list(edges.values()),
        "ext_in": [dict(v, ips=len(v["ips"])) for v in ext_in.values()],
        "ext_out": sorted(ext_out.values(), key=lambda x: -x["n"])[:40],
        "matrix": matrix,
        "diagnosis": diagnose(conf, nodes, matrix),
        "pairs": pair_units(conf, nodes),
        "speed_history": SPEED_HISTORY[-30:],
        "tune": {k: v for k, v in TUNE.items() if not k.startswith("_")},
        "settings": {k: conf.get(k) for k in ("interval", "urls", "listen", "sni")} | {"password_set": bool(conf.get("password"))},
    }


def diagnose(conf, nodes, matrix):
    iran = [n["name"] for n in conf["nodes"] if n.get("role") == "iran"]
    if not iran:
        return {"level": "info", "title": "سرور ایران تعریف نشده", "lines": []}
    src = iran[0]
    d = (nodes.get(src) or {}).get("data")
    if not d:
        return {"level": "bad", "title": "agent سرور ایران جواب نمی‌دهد", "lines": [(nodes.get(src) or {}).get("err", "")]}
    urls = (d.get("probes") or {}).get("urls", {})
    google = next((v for k, v in urls.items() if "google" in k), None)
    arvan = next((v for k, v in urls.items() if "arvan" in k), None)
    g_ok = bool(google and google.get("ok"))
    a_ok = bool(arvan and arvan.get("ok"))
    lines, ping_only, full, dead = [], [], [], []
    for n in conf["nodes"]:
        if n.get("role") == "iran":
            continue
        pr = matrix.get(src, {}).get(n["name"])
        if not pr:
            lines.append(f"{n['name']}: هنوز تست نشده")
            continue
        tcp_ok = [p for p, ms in pr["tcp"].items() if ms is not None]
        if tcp_ok:
            full.append(n["name"])
            lines.append(f"{n['name']}: وصل (پورت‌های {', '.join(tcp_ok)})")
        elif pr.get("ping_ok"):
            ping_only.append(n["name"])
            lines.append(f"{n['name']}: ping هست ولی هیچ پورت TCP باز نمی‌شود")
        else:
            dead.append(n["name"])
            lines.append(f"{n['name']}: کاملاً غیرقابل دسترس")
    if not d.get("probes", {}).get("ts"):
        return {"level": "info", "title": "در حال اولین تست…", "lines": lines}
    if not g_ok and not a_ok and not full:
        t, lv = "سرور ایران به هیچ‌جا دسترسی ندارد (مشکل خود سرور یا دیتاسنتر)", "bad"
    elif not g_ok and a_ok and not full:
        t, lv = "نوع ۳: قطع کامل / لیست سفید — فقط مسیر CDN آروان", "bad"
    elif full and g_ok:
        t, lv = "عادی: ایران به خارج وصل است (اگر کلاینت‌ها وصل نمی‌شوند، فیلتر پروتکل است → نوع ۱)", "ok"
    elif full and not g_ok:
        t, lv = "اینترنت بین‌الملل محدود است ولی بعضی سرورهای خارج در دسترس‌اند → تانل از همان‌ها (نوع ۲)", "warn"
    elif ping_only:
        t, lv = "ping هست ولی TCP بسته → DPI/بستن پورت (نوع ۱/۲): پورت یا پروتکل را عوض کنید", "warn"
    else:
        t, lv = "IP سرورهای خارج بسته شده ولی بین‌الملل وصل است → IP عوض کنید یا CDN", "warn"
    return {"level": lv, "title": t, "lines": lines,
            "google": google, "arvan": arvan}




# ---------- stacktunnel management ----------

def aget(args, flag, default=""):
    for f, v in args:
        if f == flag:
            return v
    return default


def aset(args, flag, value):
    out, done = [], False
    for f, v in args:
        if f == flag:
            if value not in (None, ""):
                out.append([f, value])
            done = True
        else:
            out.append([f, v])
    if not done and value not in (None, ""):
        out.append([flag, value])
    return out


def plist(s):
    return [int(p) for p in str(s or "").split(",") if p.strip().isdigit()]


def pjoin(ps):
    return ",".join(str(p) for p in ps)


def listen_port(tunnel):
    return tunnel.rpartition(":")[2]


def node_units(name):
    with LOCK:
        r = STATE["nodes"].get(name) or {}
        return list(((r.get("data") or r.get("stale") or {}).get("units")) or [])


def node_ips(conf, name):
    ips = set()
    for n in conf["nodes"]:
        if n["name"] == name:
            ips.add(node_ip(n))
    with LOCK:
        d = (STATE["nodes"].get(name) or {}).get("data") or {}
    ips.update(a["ip"] for a in d.get("addrs", []))
    if d.get("public_ip"):
        ips.add(d["public_ip"])
    return ips


def find_server(conf, client_args):
    """Iran node + server unit a client unit dials into (via -tunnel IP:PORT)."""
    host, _, port = aget(client_args, "tunnel").rpartition(":")
    for n in conf["nodes"]:
        if n.get("role") != "iran" or host not in node_ips(conf, n["name"]):
            continue
        for u in node_units(n["name"]):
            if aget(u["args"], "mode") == "server" and listen_port(aget(u["args"], "tunnel")) == port:
                return n["name"], u
    return None, None


def pair_units(conf, nodes):
    pairs, served = [], {}
    for n in conf["nodes"]:
        if n.get("role") == "iran":
            continue
        for u in node_units(n["name"]):
            if aget(u["args"], "mode") != "client":
                continue
            sn, su = find_server(conf, u["args"])
            if su:
                served.setdefault((sn, su["name"]), []).append(n["name"])
            pairs.append({"client_node": n["name"], "client_unit": u["name"],
                          "server_node": sn, "server_unit": su["name"] if su else None,
                          "tunnel": aget(u["args"], "tunnel"), "transport": aget(u["args"], "transport", "tcp"),
                          "tcp": plist(aget(u["args"], "ports")), "udp": plist(aget(u["args"], "udp")),
                          "client_state": (u.get("state") or {}).get("ActiveState"),
                          "server_state": ((su or {}).get("state") or {}).get("ActiveState")})
    return {"pairs": pairs, "served": [{"node": k[0], "unit": k[1], "clients": v} for k, v in served.items()]}


def live_unit(node_name, unit):
    return agent_call(get_node(node_name), "/unit/get", {"name": unit})


def listeners(node_name):
    with LOCK:
        d = (STATE["nodes"].get(node_name) or {}).get("data") or {}
    return {(l["proto"], int(l["port"])): l["proc"] for l in d.get("listen", []) if str(l["port"]).isdigit()}


def plan(changes):
    """Dry-run each change on its agent and attach the diff."""
    for c in changes:
        r = agent_call(get_node(c["node"]), "/unit/apply",
                       {"name": c["name"], "description": c["description"], "args": c["args"], "dry": True})
        c["diff"], c["changed"], c["exists"] = r.get("diff", ""), r.get("changed"), r.get("exists")
    return changes


def port_plan(node_name, unit, proto, port, op):
    conf = load_conf()
    proto = "udp" if proto == "udp" else "tcp"
    flag = "udp" if proto == "udp" else "ports"
    port = int(port)
    if not 0 < port < 65536:
        raise ValueError("bad port")
    if op not in ("add", "remove"):
        raise ValueError("op must be add/remove")
    u = live_unit(node_name, unit)
    args = [a for a in u["args"] if a[0] != "_"]
    mode = aget(args, "mode")
    changes, warnings = [], []
    cur = plist(aget(args, flag))
    if op == "add":
        if port in cur:
            raise ValueError(f"{proto} {port} is already in {unit}")
        new = cur + [port]
    else:
        if port not in cur:
            raise ValueError(f"{proto} {port} is not in {unit}")
        new = [p for p in cur if p != port]
    changes.append({"node": node_name, "name": unit, "description": u["description"],
                    "args": aset(args, flag, pjoin(new)), "old_args": args, "old_description": u["description"]})
    if mode == "client":
        sn, _ = find_server(conf, args)
        if not sn:
            warnings.append("سرور ایرانِ این تانل در پنل پیدا نشد؛ فقط سمت خارج تغییر می‌کند.")
        else:
            # the server's live unit name comes from the cached match
            _, su_cached = find_server(conf, args)
            su = live_unit(sn, su_cached["name"])
            sargs = [a for a in su["args"] if a[0] != "_"]
            scur = plist(aget(sargs, flag))
            if op == "add" and port not in scur:
                busy = listeners(sn).get((proto, port))
                if busy:
                    raise ValueError(f"port {proto}/{port} is already used on {sn} by {busy}")
                changes.append({"node": sn, "name": su["name"], "description": su["description"],
                                "args": aset(sargs, flag, pjoin(scur + [port])), "old_args": sargs,
                                "old_description": su["description"]})
            elif op == "remove" and port in scur:
                others = [p for p in pair_units(conf, None)["pairs"]
                          if p["server_node"] == sn and p["server_unit"] == su["name"]
                          and not (p["client_node"] == node_name and p["client_unit"] == unit)
                          and port in p[proto]]
                if others:
                    warnings.append(f"پورت روی سرور ایران می‌ماند چون {others[0]['client_node']} هم از آن استفاده می‌کند.")
                else:
                    changes.append({"node": sn, "name": su["name"], "description": su["description"],
                                    "args": aset(sargs, flag, pjoin([p for p in scur if p != port])),
                                    "old_args": sargs, "old_description": su["description"]})
        if op == "add" and not listeners(node_name).get((proto, port)) and proto == "tcp":
            warnings.append(f"روی {node_name} هنوز سرویسی روی پورت {port} گوش نمی‌دهد؛ بعد از اضافه شدن، اتصال تا وقتی سرویس بالا بیاید کار نمی‌کند.")
    elif mode == "server" and op == "add":
        busy = listeners(node_name).get((proto, port))
        if busy:
            raise ValueError(f"port {proto}/{port} is already used on {node_name} by {busy}")
    if any(get_node(c["node"]).get("role") == "iran" for c in changes):
        warnings.append("سرویس سمت ایران ری‌استارت می‌شود: همه‌ی کاربرهای این تانل چند ثانیه قطع و دوباره وصل می‌شوند.")
    # server side first when adding (port exists before clients use it), client first when removing
    if op == "add":
        changes.sort(key=lambda c: 0 if get_node(c["node"]).get("role") == "iran" else 1)
    return {"changes": plan(changes), "warnings": warnings}


def tunnel_plan(p):
    conf = load_conf()
    iran, kharej = get_node(p.get("iran", "")), get_node(p.get("kharej", ""))
    if iran.get("role") != "iran" or kharej.get("role") == "iran":
        raise ValueError("pick one Iran server and one foreign server")
    suffix = str(p.get("name", "")).strip().lower()
    if not re.fullmatch(r"[a-z0-9]{1,16}", suffix):
        raise ValueError("name: 1-16 lowercase letters/digits")
    name = "stacktunnel-" + suffix
    tport = int(p.get("tunnel_port", 0))
    if not 0 < tport < 65536:
        raise ValueError("tunnel port required")
    if any(u["name"] == name for u in node_units(iran["name"]) + node_units(kharej["name"])):
        raise ValueError(f"{name} already exists")
    if listeners(iran["name"]).get(("tcp", tport)) or listeners(iran["name"]).get(("udp", tport)):
        raise ValueError(f"tunnel port {tport} is already in use on {iran['name']}")
    key = p.get("key") or secrets.token_hex(24)
    transport = p.get("transport") or "tcp"
    common = [["key", key], ["transport", transport], ["pad", str(p.get("pad", 128))]]
    sargs = [["mode", "server"], ["tunnel", f":{tport}"]] + common
    cargs = [["mode", "client"], ["tunnel", f"{node_ip(iran)}:{tport}"]] + common + \
            [["conns", str(p.get("conns", 4))], ["rotate", str(p.get("rotate", "5m"))]]
    for flag in ("ports", "udp"):
        v = pjoin(plist(p.get(flag)))
        if v:
            for pt in plist(v):
                if listeners(iran["name"]).get(("udp" if flag == "udp" else "tcp", pt)):
                    raise ValueError(f"port {pt} is already in use on {iran['name']}")
            sargs.append([flag, v])
            cargs.append([flag, v])
    desc = f"StackTunnel {suffix}"
    changes = [{"node": iran["name"], "name": name, "description": desc + " (server)", "args": sargs, "old_args": None},
               {"node": kharej["name"], "name": name, "description": desc + " (client)", "args": cargs, "old_args": None}]
    return {"changes": plan(changes), "warnings": ["کلید تانل خودکار ساخته شد و روی هر دو طرف یکسان است."]}


def apply_changes(changes):
    done, results = [], []
    for c in changes:
        try:
            r = agent_call(get_node(c["node"]), "/unit/apply",
                           {"name": c["name"], "description": c["description"], "args": c["args"]}, timeout=40)
        except Exception as e:
            r = {"ok": False, "error": str(e)}
        r.update(node=c["node"], name=c["name"])
        results.append(r)
        if not r.get("ok"):
            # undo the steps that already went through
            for d in reversed(done):
                try:
                    if d.get("old_args"):
                        agent_call(get_node(d["node"]), "/unit/apply",
                                   {"name": d["name"], "description": d.get("old_description") or d["description"],
                                    "args": d["old_args"]}, timeout=40)
                    else:
                        agent_call(get_node(d["node"]), "/unit/delete", {"name": d["name"]}, timeout=40)
                    results.append({"node": d["node"], "name": d["name"], "ok": True, "undone": True})
                except Exception as e:
                    results.append({"node": d["node"], "name": d["name"], "ok": False, "undo_error": str(e)})
            break
        done.append(c)
    for n in {c["node"] for c in changes}:
        poll_node(n)
    return {"ok": all(r.get("ok") for r in results if not r.get("undone")) and len(done) == len(changes),
            "results": results}


# ---------- speed tests ----------

def _record(res):
    res["ts"] = int(time.time())
    if res.get("secs"):
        res["mbps"] = round(res["bytes"] * 8 / res["secs"] / 1e6, 2)
    res["stalled"] = res.get("bytes", 0) < res.get("want", 0)
    SPEED_HISTORY.append(res)
    del SPEED_HISTORY[:-50]
    return res


def speed_direct(node, direction, mb):
    n = int(mb * 1024 * 1024)
    res = {"node": node["name"], "mode": "direct", "dir": direction, "want": n, "bytes": 0}
    deadline = 30
    t = time.time()
    try:
        c = _conn(node, 15)
        c.sock.settimeout(10)
        try:
            if direction == "down":
                c.request("GET", f"/speed/down/{n}", headers={"Authorization": "Bearer " + node["token"]})
                r = c.getresponse()
                while res["bytes"] < n and time.time() - t < deadline:
                    d = r.read(65536)
                    if not d:
                        break
                    res["bytes"] += len(d)
            else:
                c.putrequest("POST", "/speed/up")
                c.putheader("Authorization", "Bearer " + node["token"])
                c.putheader("Content-Length", str(n))
                c.endheaders()
                chunk = os.urandom(65536)
                while res["bytes"] < n and time.time() - t < deadline:
                    k = min(len(chunk), n - res["bytes"])
                    c.send(chunk[:k])
                    res["bytes"] += k
                if res["bytes"] >= n:
                    got = json.loads(c.getresponse().read())
                    res["bytes"] = got.get("bytes", res["bytes"])
        finally:
            c.close()
    except Exception as e:
        res["err"] = f"{type(e).__name__}: {e}"[:160]
    res["secs"] = round(time.time() - t, 3)
    return _record(res)


def speed_tunnel(node, port, mb, streams=1):
    """Download through the tunnel: N parallel streams, each fetching its share of the bytes."""
    streams = max(1, min(int(streams), 16))
    n = int(mb * 1024 * 1024)
    res = {"node": node["name"], "mode": "tunnel", "dir": "down", "port": port, "want": n, "bytes": 0,
           "streams": streams}
    try:
        agent_call(node, "/speed/listen", {"port": port, "seconds": 60})
    except Exception as e:
        res["err"] = str(e)[:200]
        return _record(res)
    time.sleep(0.3)
    got, errs, lock = [0], [], threading.Lock()
    t = time.time()

    def one(share):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            s.settimeout(10)
            try:
                s.sendall(f"{share}\n".encode())
                left = share
                while left > 0 and time.time() - t < 30:
                    d = s.recv(65536)
                    if not d:
                        break
                    left -= len(d)
                    with lock:
                        got[0] += len(d)
            finally:
                s.close()
        except Exception as e:
            errs.append(f"{type(e).__name__}: {e}"[:160])

    shares = [n // streams + (1 if i < n % streams else 0) for i in range(streams)]
    th = [threading.Thread(target=one, args=(sh,), daemon=True) for sh in shares]
    for x in th:
        x.start()
    for x in th:
        x.join(35)
    res["bytes"] = got[0]
    if errs:
        res["err"] = errs[0]
    res["secs"] = round(time.time() - t, 3)
    return _record(res)



# ---------- auto-tune: find the best conns/window/transport ----------

TUNE_NAME = "stacktunnel-tune"
TUNE = {"running": False, "cancel": False, "results": [], "log": [], "params": None,
        "started": 0, "finished": 0, "done": 0, "total": 0, "current": None, "error": None}
TUNE_LOCK = threading.Lock()


def _tlog(msg):
    TUNE["log"].append(time.strftime("%H:%M:%S ") + msg)
    del TUNE["log"][:-60]


def _ints(v, lo, hi, name):
    out = sorted({int(x) for x in str(v).replace(" ", "").split(",") if x.strip().isdigit()})
    if not out or any(not lo <= x <= hi for x in out):
        raise ValueError(f"{name}: comma list of numbers {lo}..{hi}")
    return out


def _tune_cleanup(iran, kharej):
    for n in (kharej, iran):
        try:
            agent_call(get_node(n), "/unit/delete", {"name": TUNE_NAME}, timeout=30)
        except Exception:
            pass


def tune_start(b):
    iran = b.get("iran") or next((n["name"] for n in load_conf()["nodes"] if n.get("role") == "iran"), None)
    kh = get_node(b.get("kharej", ""))
    if kh.get("role") == "iran" or get_node(iran).get("role") != "iran":
        raise ValueError("pick a foreign server")
    params = {
        "iran": iran, "kharej": kh["name"],
        "conns": _ints(b.get("conns", "2,4,8"), 1, 64, "conns"),
        "windows": _ints(b.get("windows", "256,1024,4096"), 16, 65536, "window"),
        "transports": [t for t in (b.get("transports") or ["tcp"]) if t in ("tcp", "udp")] or ["tcp"],
        "mb": max(1, min(float(b.get("mb", 10)), 50)),
        "repeats": max(1, min(int(b.get("repeats", 2)), 5)),
        "tunnel_port": int(b.get("tunnel_port", 4900)),
        "test_port": int(b.get("test_port", 9557)),
        "pad": int(b.get("pad", 128)),
        "streams": max(1, min(int(b.get("streams", 4)), 16)),
    }
    total = len(params["conns"]) * len(params["windows"]) * len(params["transports"])
    if total > 40:
        raise ValueError(f"{total} combinations is too many (max 40)")
    with TUNE_LOCK:
        if TUNE["running"]:
            raise ValueError("a tuning run is already in progress")
        TUNE.update(running=True, cancel=False, results=[], log=[], params=params, started=int(time.time()),
                    finished=0, done=0, total=total, current=None, error=None)
    threading.Thread(target=tune_run, args=(params,), daemon=True).start()
    return {"ok": True, "total": total}


def tune_run(p):
    iran, kh = p["iran"], p["kharej"]
    try:
        _tune_cleanup(iran, kh)  # leftovers from an interrupted run
        poll_node(iran); poll_node(kh)
        created = False
        for tr in p["transports"]:
            for w in p["windows"]:
                for c in p["conns"]:
                    if TUNE["cancel"]:
                        _tlog("لغو شد")
                        return
                    TUNE["current"] = {"transport": tr, "conns": c, "window": w}
                    if not created or TUNE.get("_tr") != tr:
                        if created:
                            _tune_cleanup(iran, kh); poll_node(iran); poll_node(kh)
                        pl = tunnel_plan({"iran": iran, "kharej": kh, "name": "tune", "tunnel_port": p["tunnel_port"],
                                          "transport": tr, "ports": str(p["test_port"]), "pad": p["pad"],
                                          "conns": c, "rotate": "0"})
                        for ch in pl["changes"]:
                            ch["name"] = TUNE_NAME
                        r = apply_changes(pl["changes"])
                        if not r["ok"]:
                            raise RuntimeError("could not start the test tunnel: " +
                                               "; ".join(str(x.get("error", "")) for x in r["results"] if not x.get("ok")))
                        created, TUNE["_tr"] = True, tr
                        _tlog(f"تانل تست با {tr} ساخته شد")
                    # window must match on both ends (stacktunnel docs); conns is client-only
                    r = {"ok": True}
                    for node_name, flags in ((iran, {"window": w}), (kh, {"conns": c, "window": w})):
                        u = live_unit(node_name, TUNE_NAME)
                        args = [a for a in u["args"] if a[0] != "_" and a[0] not in flags] + \
                               [[k, str(v)] for k, v in flags.items()]
                        r = agent_call(get_node(node_name), "/unit/apply",
                                       {"name": TUNE_NAME, "description": u["description"], "args": args}, timeout=40)
                        if not r.get("ok"):
                            break
                    row = {"transport": tr, "conns": c, "window": w, "runs": []}
                    if not r.get("ok"):
                        row["err"] = r.get("error", "apply failed")
                    else:
                        time.sleep(3)
                        for _ in range(p["repeats"]):
                            if TUNE["cancel"]:
                                break
                            s = speed_tunnel(get_node(kh), p["test_port"], p["mb"], p["streams"])
                            SPEED_HISTORY.pop()  # keep the speed tab for manual tests
                            row["runs"].append({k: s.get(k) for k in ("mbps", "bytes", "want", "secs", "err", "stalled")})
                            time.sleep(1)
                    ok = [x["mbps"] or 0 for x in row["runs"] if not x.get("err")]
                    row["mbps"] = round(sum(ok) / len(ok), 2) if ok else 0
                    row["min"] = round(min(ok), 2) if ok else 0
                    row["stalled"] = any(x.get("stalled") for x in row["runs"])
                    row["err"] = row.get("err") or "; ".join({x["err"] for x in row["runs"] if x.get("err")})
                    TUNE["results"].append(row)
                    TUNE["done"] += 1
                    _tlog(f"{tr} conns={c} window={w}KB → {row['mbps']} Mbps")
    except Exception as e:
        TUNE["error"] = f"{type(e).__name__}: {e}"[:300]
        _tlog("خطا: " + TUNE["error"])
    finally:
        _tune_cleanup(iran, kh)
        poll_node(iran); poll_node(kh)
        TUNE.update(running=False, current=None, finished=int(time.time()))
        TUNE.pop("_tr", None)
        _tlog("تانل تست پاک شد")


def tune_apply_plan(b):
    """Plan putting a tested conns/window onto the server's real client unit (preview first)."""
    kh, unit = b["kharej"], b["unit"]
    u = live_unit(kh, unit)
    args = [a for a in u["args"] if a[0] != "_"]
    if aget(args, "mode") != "client":
        raise ValueError("pick the client unit on the foreign server")
    w = str(int(b["window"]))
    old_args = list(args)
    args = aset(aset(args, "conns", str(int(b["conns"]))), "window", w)
    ch = [{"node": kh, "name": unit, "description": u["description"], "args": args,
           "old_args": old_args, "old_description": u["description"]}]
    warn = []
    conf = load_conf()
    sn, su = find_server(conf, old_args)
    if su and aget(su["args"], "window", "1024") != w:
        live = live_unit(sn, su["name"])
        sargs = [a for a in live["args"] if a[0] != "_"]
        ch.insert(0, {"node": sn, "name": su["name"], "description": live["description"],
                      "args": aset(sargs, "window", w), "old_args": sargs, "old_description": live["description"]})
        others = [p["client_node"] for p in pair_units(conf, None)["pairs"]
                  if p["server_node"] == sn and p["server_unit"] == su["name"] and p["client_node"] != kh]
        warn.append(f"window باید روی هر دو طرف یکی باشد، پس سرویس {su['name']} روی {sn} هم {w} می‌شود و ری‌استارت می‌شود"
                    + (f"؛ این سرویس به {', '.join(others)} هم خدمت می‌دهد — window آن‌ها را هم یکی کنید." if others else "."))
    warn.append("سرویس سرور خارج ری‌استارت می‌شود؛ کاربرهای آن چند ثانیه قطع و وصل می‌شوند.")
    if b.get("transport") and b["transport"] != "tcp":
        warn.append("transport در تست " + b["transport"] + " بوده؛ این دکمه فقط conns و window را عوض می‌کند. "
                    "برای عوض کردن transport، سرویس را در تب تانل‌ها ویرایش کنید (سمت ایران هم باید آن را داشته باشد).")
    return {"changes": plan(ch), "warnings": warn}


# ---------- web ----------

def api(path, b):
    conf = load_conf()
    if path == "/api/refresh":
        threading.Thread(target=poll_once, daemon=True).start()
        return {"ok": True}
    if path == "/api/nodes/add":
        node = {"name": str(b.get("name", "")).strip(), "role": b.get("role"), "host": str(b.get("host", "")).strip(),
                "port": int(b.get("port") or 9555), "token": str(b.get("token", "")).strip(),
                "fp": str(b.get("fp", "")).replace(":", "").strip().lower(),
                "probe_ports": plist(b.get("probe_ports") or "443") or [443], "note": str(b.get("note", ""))[:100]}
        if b.get("ip"):
            node["ip"] = str(b["ip"]).strip()
        if b.get("sni"):
            node["sni"] = str(b["sni"]).strip()
        if not NAME_RE.fullmatch(node["name"]) or node["role"] not in ("iran", "kharej"):
            raise ValueError("name (letters/digits/-) and role are required")
        if not re.fullmatch(r"[0-9a-f]{64}", node["fp"]) or len(node["token"]) < 16:
            raise ValueError("token and fingerprint are required (printed by the agent installer)")
        fetch(node, conf)  # must answer before we save it
        with CONF_LOCK:
            conf = load_conf()
            conf["nodes"] = [n for n in conf["nodes"] if n["name"] != node["name"]] + [node]
            save_conf(conf)
        poll_node(node["name"])
        return {"ok": True}
    if path == "/api/nodes/del":
        with CONF_LOCK:
            conf = load_conf()
            conf["nodes"] = [n for n in conf["nodes"] if n["name"] != b.get("name")]
            save_conf(conf)
        with LOCK:
            STATE["nodes"].pop(b.get("name"), None)
        return {"ok": True}
    if path == "/api/nodes/rename":
        old_n, new_n = str(b.get("name", "")), str(b.get("new", "")).strip()
        if not NAME_RE.fullmatch(new_n):
            raise ValueError("new name: letters, digits, - or _ (max 32)")
        with CONF_LOCK:
            conf = load_conf()
            if new_n != old_n and any(n["name"] == new_n for n in conf["nodes"]):
                raise ValueError(f"{new_n} already exists")
            for n in conf["nodes"]:
                if n["name"] == old_n:
                    n["name"] = new_n
                    if "note" in b:
                        n["note"] = str(b["note"])[:100]
                    break
            else:
                raise ValueError(f"unknown server {old_n}")
            save_conf(conf)
        with LOCK:
            if old_n in STATE["nodes"]:
                STATE["nodes"][new_n] = STATE["nodes"].pop(old_n)
        return {"ok": True}
    if path == "/api/settings":
        with CONF_LOCK:
            conf = load_conf()
            if "interval" in b:
                conf["interval"] = max(5, min(int(b["interval"]), 600))
            if "urls" in b:
                conf["urls"] = [u for u in b["urls"] if re.match(r"^https?://[A-Za-z0-9.\-]+(:\d+)?(/\S*)?$", u)][:6]
            if b.get("password") is not None:
                conf["password"] = str(b["password"])
            if "sni" in b:
                v = str(b["sni"]).strip()
                if v and not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", v):
                    raise ValueError("bad SNI")
                conf["sni"] = v
            save_conf(conf)
        return {"ok": True}
    if path == "/api/unit/get":
        return live_unit(b["node"], b["name"])
    if path == "/api/unit/plan":
        u_args = [[str(f), str(v)] for f, v in b.get("args", [])]
        old = None
        try:
            lu = live_unit(b["node"], b["name"])
            old = [a for a in lu["args"] if a[0] != "_"]
            old_desc = lu["description"]
        except Exception:
            old_desc = None
        ch = [{"node": b["node"], "name": b["name"], "description": b.get("description", ""), "args": u_args,
               "old_args": old, "old_description": old_desc}]
        warn = ["سرویس ری‌استارت می‌شود و کاربرهایش چند ثانیه قطع می‌شوند."] if old else []
        return {"changes": plan(ch), "warnings": warn}
    if path == "/api/port/plan":
        return port_plan(b["node"], b["unit"], b.get("proto", "tcp"), b.get("port", 0), b.get("op", "add"))
    if path == "/api/tunnel/plan":
        return tunnel_plan(b)
    if path == "/api/apply":
        ch = b.get("changes") or []
        for c in ch:
            get_node(c["node"])
        return apply_changes(ch)
    if path == "/api/unit/action":
        r = agent_call(get_node(b["node"]), "/unit/action", {"name": b["name"], "action": b["action"]}, timeout=30)
        poll_node(b["node"])
        return r
    if path == "/api/unit/delete":
        r = agent_call(get_node(b["node"]), "/unit/delete", {"name": b["name"]}, timeout=30)
        poll_node(b["node"])
        return r
    if path == "/api/unit/logs":
        return agent_call(get_node(b["node"]), "/unit/logs", {"name": b["name"], "n": b.get("n", 120)})
    if path == "/api/unit/restore":
        r = agent_call(get_node(b["node"]), "/unit/restore", {"name": b["name"], "backup": b["backup"]}, timeout=40)
        poll_node(b["node"])
        return r
    if path == "/api/speed":
        node = get_node(b["node"])
        mb = max(0.1, min(float(b.get("mb", 10)), 100))
        if b.get("mode") == "tunnel":
            return speed_tunnel(node, int(b.get("port", 0)), mb)
        if node.get("role") == "iran":
            raise ValueError("direct test is from the Iran server to a foreign server; pick a foreign server")
        return speed_direct(node, "up" if b.get("dir") == "up" else "down", mb)
    if path == "/api/tune/start":
        return tune_start(b)
    if path == "/api/tune/cancel":
        TUNE["cancel"] = True
        return {"ok": True}
    if path == "/api/tune/apply":
        return tune_apply_plan(b)
    raise LookupError(path)


class H(BaseHTTPRequestHandler):
    server_version = "stacktunnel-panel"
    timeout = 120

    def log_message(self, *a):
        pass

    def auth(self):
        pw = load_conf().get("password")
        if not pw:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                _, _, given = base64.b64decode(h[6:]).decode().partition(":")
                if hmac.compare_digest(given.encode(), pw.encode()):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="StackTunnel"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def send(self, code, ctype, data):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def sendj(self, code, obj):
        self.send(code, "application/json", json.dumps(obj, ensure_ascii=False).encode())

    def do_GET(self):
        if not self.auth():
            return
        if self.path == "/api/state":
            return self.sendj(200, analyse())
        if self.path in ("/", "/index.html"):
            return self.send(200, "text/html; charset=utf-8", page())
        self.send(404, "text/plain", b"not found")

    def do_POST(self):
        if not self.auth():
            return
        # same-origin only (blocks other websites from driving the panel through your browser)
        origin = self.headers.get("Origin")
        if origin and origin.split("://", 1)[-1] != self.headers.get("Host"):
            return self.sendj(403, {"ok": False, "error": "cross-origin request refused"})
        try:
            b = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 1 << 20)) or b"{}")
            return self.sendj(200, api(self.path, b))
        except LookupError:
            return self.send(404, "text/plain", b"not found")
        except (ValueError, KeyError) as e:
            return self.sendj(400, {"ok": False, "error": str(e)})
        except Exception as e:
            return self.sendj(500, {"ok": False, "error": f"{type(e).__name__}: {e}"})


def page():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "panel.html")
    with open(p, "rb") as f:
        return f.read()


def serve():
    conf = load_conf()
    host, _, port = conf["listen"].rpartition(":")
    if host not in ("127.0.0.1", "localhost", "::1") and not conf.get("password"):
        sys.exit("panel listens on a public address: set \"password\" in panel.json first")
    threading.Thread(target=poller, daemon=True).start()
    print(f"StackTunnel Panel {VERSION} on http://{host}:{port}", flush=True)
    ThreadingHTTPServer((host, int(port)), H).serve_forever()


def cli():
    if len(sys.argv) == 1:
        return serve()
    ap = argparse.ArgumentParser(prog="stacktunnel-panel")
    sp = ap.add_subparsers(dest="cmd", required=True)
    a = sp.add_parser("add-node", help="add or replace a server")
    a.add_argument("--name", required=True)
    a.add_argument("--role", choices=["iran", "kharej"], required=True)
    a.add_argument("--host", required=True)
    a.add_argument("--ip")
    a.add_argument("--port", type=int, default=9555)
    a.add_argument("--token", required=True)
    a.add_argument("--fp", required=True)
    a.add_argument("--probe-ports", default="443")
    a.add_argument("--note", default="")
    d = sp.add_parser("del-node")
    d.add_argument("name")
    sp.add_parser("list")
    sp.add_parser("serve")
    args = ap.parse_args()
    if args.cmd == "serve":
        return serve()
    with CONF_LOCK:
        conf = load_conf()
        if args.cmd == "list":
            for n in conf["nodes"]:
                print(f"{n['name']:<14} {n['role']:<7} {n['host']}:{n.get('port', 9555)}  probe={n.get('probe_ports')}  {n.get('note', '')}")
            return
        if args.cmd == "del-node":
            conf["nodes"] = [n for n in conf["nodes"] if n["name"] != args.name]
            save_conf(conf)
            return print("removed", args.name)
        node = {"name": args.name, "role": args.role, "host": args.host, "port": args.port,
                "token": args.token, "fp": args.fp.replace(":", "").lower(),
                "probe_ports": plist(args.probe_ports) or [443], "note": args.note}
        if args.ip:
            node["ip"] = args.ip
        conf["nodes"] = [n for n in conf["nodes"] if n["name"] != args.name] + [node]
        save_conf(conf)
    print("saved", args.name, "(picked up on the next poll)")


if __name__ == "__main__":
    cli()
