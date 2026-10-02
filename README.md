# StackTunnel

**English** | [فارسی](README.fa.md)

A small reverse TCP/UDP tunnel for restricted networks. One static binary, one shared key, and an interactive installer that sets it up as a systemd service.

> **Status:** tested on real servers and working there, but it may not work on some networks. It has not been independently audited. Read [Security notes](#security-notes) and [Limitations](#limitations) before relying on it.

## Overview

Two servers are involved:

- **Inside server**: the one your users connect to.
- **Outside server**: the one that runs your real service (proxy, VPN, …) and connects *to* the inside server.

```
 user ──► INSIDE server :443 ═══ tunnel ═══ OUTSIDE server ──► 127.0.0.1:443 (your service)
```

You can connect several outside servers to one inside server (each serving different ports), or one outside server to several inside servers.

## Install

On **both** servers:

```bash
curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/setup.sh -o setup.sh
sudo bash setup.sh
```

The installer downloads the right binary for your CPU from the latest [Release](https://github.com/stacktunnel/Tunnel/releases), verifies it against `SHA256SUMS`, and sets it up as a service.

1. Run it on the **inside** server first and choose `1) Iran server`. Let it generate a key and write the key down.
2. Run it on the **outside** server and choose `2) Kharej server`. Enter the inside server's IP, the same key and the same ports.

It installs `/usr/local/bin/stacktunnel`, saves settings in `/etc/stacktunnel/config.env`, creates `stacktunnel.service` (restarts automatically, enabled at boot) and can open the needed ports in `ufw`.

```bash
sudo bash setup.sh status | logs | restart | update | show | uninstall
```

Make sure your real service on the outside server listens on `127.0.0.1` on the same ports you forward, and that the tunnel port (default `4000`) is open on the inside server's firewall.

### Updating

```bash
sudo bash setup.sh update
```

Releases are **not compatible with each other**: update the inside and the outside servers together.

### If a server cannot reach GitHub

Download the file for your CPU from the Releases page on another machine, then copy it next to `setup.sh` on the server, renamed to `stacktunnel`:

| File | For |
|---|---|
| `stacktunnel-linux-amd64` | most servers (x86-64) |
| `stacktunnel-linux-arm64` | 64-bit ARM servers |
| `stacktunnel-linux-armv7` | 32-bit ARM (Raspberry Pi and similar) |
| `stacktunnel-android-arm64` | Android phones (see [Android](#android)) |
| `SHA256SUMS` | checksums |

```bash
sha256sum -c SHA256SUMS --ignore-missing      # on the machine where you downloaded
scp stacktunnel-linux-amd64 root@SERVER:~/stacktunnel
```

`setup.sh` uses a `stacktunnel` file in its own directory if one exists, instead of downloading.

## Versioning

Releases follow [Semantic Versioning](https://semver.org) (`v0.1.0`, `v0.1.1`, …). Check what is installed with:

```bash
stacktunnel -version
```

While the major version is `0`, a change in the **minor** number (`0.1.x` → `0.2.0`) may break compatibility between servers, so update the inside and outside servers together. Patch releases are compatible with each other. See [CHANGELOG.md](CHANGELOG.md).

## Other platforms

Every release also contains binaries for macOS (`darwin-amd64`, `darwin-arm64`), Windows (`windows-amd64.exe`, `windows-arm64.exe`) and FreeBSD (`freebsd-amd64`). `setup.sh` supports **Linux with systemd** only; on other systems download the binary for your platform and run it manually as described below.

## Android

**Experimental.** The Android binary is a command-line program, not an app. The easiest way to run it is [Termux](https://termux.dev) (install it from F-Droid or from its GitHub releases; the Play Store version is outdated).

```bash
# inside Termux
pkg install curl
curl -fsSLO https://github.com/stacktunnel/Tunnel/releases/latest/download/stacktunnel-android-arm64
curl -fsSLO https://github.com/stacktunnel/Tunnel/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
mv stacktunnel-android-arm64 stacktunnel && chmod +x stacktunnel
./stacktunnel -version
```

Run it as described in [Manual usage](#manual-usage), for example as the outside (client) side:

```bash
termux-wake-lock
./stacktunnel -mode client -key SECRET -tunnel INSIDE_IP:4000 -ports 443 -conns 2
```

Notes:

- Use **IP addresses**, not host names, for `-tunnel`.
- `setup.sh` does not work on Android (no systemd). Disable battery optimisation for Termux and use `termux-wake-lock` so Android does not stop the process.
- Only 64-bit ARM phones (`android-arm64`) have a dedicated binary. On 32-bit ARM phones, try `stacktunnel-linux-armv7` inside Termux.
- A phone is normally behind NAT, so it is usually only useful as the **outside (client)** side, not as the server that users connect to.

## Build from source

Requires Go 1.18 or newer.

```bash
git clone https://github.com/stacktunnel/Tunnel.git
cd Tunnel
go build -trimpath -ldflags="-s -w" -o stacktunnel .
```

Releases are built automatically by GitHub Actions when a tag such as `v0.1.0` is pushed.

## Manual usage

**Inside server:**

```bash
./stacktunnel -mode server -key SECRET -tunnel :4000 -ports 443,8000-8100 -udp 51820
```

**Outside server:**

```bash
./stacktunnel -mode client -key SECRET -tunnel INSIDE_IP:4000 -ports 443,8000-8100 -udp 51820 -conns 4
```

Users connect to `INSIDE_IP:443` (TCP) or `INSIDE_IP:51820` (UDP) and reach `127.0.0.1` on the same port of the outside server.

### Flags

| Flag | Mode | Description |
|---|---|---|
| `-mode` | both | `server` (inside) or `client` (outside) |
| `-key` | both | Shared key; must be identical on every server |
| `-tunnel` | both | server: listen address, e.g. `:4000`. client: `IP:port`, or a comma-separated list `IP1:4000,IP2:4001` |
| `-ports` | both | TCP ports/ranges, e.g. `443,2053,8000-8100` (a range may span up to 2000 ports) |
| `-udp` | both | UDP ports/ranges |
| `-pad` | both | Maximum random padding per frame in bytes (default `128`, `0` = off, max `4096`) |
| `-conns` | client | Parallel tunnel connections per inside server (default `4`) |
| `-bind` | server | IP the user-facing ports listen on (default: all interfaces) |

### Several servers

- The **server's** `-ports` / `-udp` decide what it offers to users.
- The **client's** `-ports` / `-udp` decide what it can serve. If it connects to several inside servers, give it the combined list of ports.
- A user connection is sent only to an outside server that serves that port. If several do, the load is shared.
- Port numbers are the same on both sides; there is no port remapping.

## Troubleshooting

Start with `sudo bash setup.sh logs`.

| Log message | Meaning |
|---|---|
| `tunnel up from … : N tcp / M udp ports` (inside) | An outside server connected |
| `connected to IP:port` (outside) | Connection established |
| `disconnected: …` (outside) | Connection lost or rejected: check key, IP/port, firewall. It retries automatically |
| `… dropped, no kharej client has announced this port` (inside) | A user connected but no outside server serves that port: it is down, or its `-ports` lacks it |
| `cannot connect to local service 127.0.0.1:P` (outside) | Your real service is not running or not listening on `127.0.0.1:P` |
| `request for tcp port P refused: not in this client's -ports` (outside) | The inside server offers a port this outside server was not configured for |

Also check: tunnel port open on the inside server, the **same key** everywhere, and the **same release version** on every server (versions are not compatible with each other).

## Speed test

A simple way to measure throughput through the tunnel, using a test file on the outside server:

```bash
# outside server: create a 200 MB file and serve it on localhost
head -c 200000000 /dev/urandom > big.bin
python3 -m http.server 8080 --bind 127.0.0.1 &
./stacktunnel -mode client -key KEY -tunnel INSIDE_IP:4100 -ports 8080 -conns 4
# inside server
./stacktunnel -mode server -key KEY -tunnel :4100 -ports 8080
curl -o /dev/null -w "%{speed_download} bytes/s\n" http://127.0.0.1:8080/big.bin
```

Use the `setup.sh` service for normal operation; this is a temporary test only (stop both test processes afterwards). Real throughput depends on the path between your servers; try `-conns 4` to `8` and several downloads in parallel.

## Security notes

- Traffic is encrypted with a **static shared key**. There is **no forward secrecy**: if the key leaks, recorded traffic can be decrypted.
- The cryptographic design is custom and **has not been independently reviewed**. Use a long random key (the installer generates one). For sensitive traffic, run a well-vetted protocol inside the tunnel.
- The outside server only connects to `127.0.0.1` on ports in its own list, and the inside server only opens ports from its own list.
- Your real service sees all connections coming from `127.0.0.1`, not the users' real IPs.
- The key is stored in a root-only (`600`) file and appears on the process command line.

## Limitations

- UDP is carried over the same connection as TCP, so packet loss can cause delay spikes. It is not suited to games or voice calls.
- No per-user accounting, web UI or authentication beyond the shared key.
- Not guaranteed to work on every network or to keep working if the network changes.

## Disclaimer

Provided **as is**, without warranty of any kind. You are responsible for complying with the laws that apply to you; tools of this kind are restricted in some jurisdictions. Do not use it to access systems you are not authorised to use.

## License

Free for **non-commercial** use under the [PolyForm Noncommercial License 1.0.0](LICENSE). You may use, modify and share it for personal, hobby, research, educational, charitable and similar non-commercial purposes. **Commercial use is not permitted** (for example selling it, or selling a service built on it); read the license for the exact terms.

This is a *source-available* license, not an OSI-approved "open source" license.

For a commercial license, contact: _add your contact (e-mail or link) here_.

## Third-party notices

The binaries include [hashicorp/yamux](https://github.com/hashicorp/yamux) (MPL-2.0), [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) and the Go standard library (BSD-3-Clause). Their license texts are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
