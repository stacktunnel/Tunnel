# Changelog

This project uses [Semantic Versioning](https://semver.org). While the major version is `0`,
a change in the **minor** number (`0.1.x` → `0.2.0`) may break compatibility between servers,
so update the inside and the outside server together. Patch releases (`0.1.0` → `0.1.1`) are
compatible with each other.

## [0.4.3]

- `setup.sh` only, no binary change. `add-ws-service` (0.4.2) now takes a
  name, so you can run SEVERAL standalone ws services at once - one per
  front/provider (e.g. `arvan`, `aws`, `cloudrun`), each its own
  `stacktunnel-ws-<name>` unit, own port(s), own `-ws-host`. Previously it
  always used one fixed service name, so a second run silently overwrote
  the first.
- New: `list-ws-services` (menu 13) lists them; `remove-ws-service NAME`
  (menu 14) removes one.
- `status` now shows every `stacktunnel-ws-*` service's status/log, not
  just a single fixed one.

## [0.4.2]

- `setup.sh` only, no binary change. Added a second, independent way to run
  ws: `add-ws-service` (menu option 11) sets it up as a genuinely standalone
  `stacktunnel-ws` service, with its own exposed port(s), separate from the
  primary tcp/udp service - instead of merging into the same process/pool
  the way `enable-ws` (option 10) does. Point a separate outbound/inbound at
  its port (e.g. a second x-ui inbound) and switch between them with your
  own panel's balancer rather than this program's pool/failover. No port
  conflict with the primary service, since they use different ports, and no
  shared pool is needed, since nothing here relies on this program's own
  failover.
- Added `disable-transport NAME` (menu option 12) to remove a transport
  from the primary service's `-transport` list (undoes `enable-udp`/
  `enable-ws`), for switching a transport over to its own standalone service
  instead, or just dropping it.
- `status` now also shows `stacktunnel-ws`'s status/log when that standalone
  service exists.

## [0.4.1]

- Fix: the ws transport has always assumed -mode client dials and -mode
  server listens, same as tcp/udp. But ws's whole point is to let the side
  with restrictive outbound connectivity (usually the Iran server) reach out
  through a CDN/front - which on this project is -mode server, the side that
  would otherwise listen. Running `enable-ws` on the kharej/outside box
  (-mode client) therefore always asked for a hostname to dial, even when
  that box needed to listen behind its own nginx - there was no way to tell
  it to do the opposite of what -mode already implies for ws. New flag
  `-ws-reverse`: for ws only (tcp/udp are unaffected), -mode server dials out
  (-ws-host/-ws-port) and -mode client listens (-ws-listen) instead.
  `setup.sh enable-ws` now asks directly which role THIS machine plays for ws
  (dial or listen) rather than assuming it from -mode, and sets -ws-reverse
  when that disagrees with the normal direction.

## [0.4.0]

- Fix (real one this time): running a second transport as a second,
  independent stacktunnel process (what `enable-udp`/`enable-ws` did
  through 0.3.2, and what `add-udp-service.sh` always did) cannot give
  automatic failover, because `pool` lives in one process's memory - a
  second process has its own, disconnected pool, and on the server side
  both processes also tried to bind the very same exposed TCP ports,
  which crash-loops with `bind: address already in use` the moment both
  are actually running. This was a real design mistake from an earlier
  session, not caught until now because `enable-udp`/`enable-ws` had
  never actually been exercised end-to-end before.
- `-transport` now takes a comma-separated list (`tcp`, `udp`, `ws`, any
  combination, e.g. `-transport tcp,udp`). A single value behaves exactly
  as before. Listing more than one now runs every one of them inside the
  SAME process: the server binds its exposed ports once and runs one
  accept loop per transport into one shared pool; the client dials every
  transport in parallel. This is what actually gives automatic failover -
  if one gets blocked, the others already have live connections in the
  same pool, with nothing further to wire up.
- New flag `-ws-listen`: when `ws` is combined with `tcp` on the server,
  they can't both bind the same TCP address, so this is now required to
  give `ws` a separate one (the server refuses to start with a clear error
  if it's missing rather than silently conflicting).
- `setup.sh`'s `enable-udp`/`enable-ws` (and menu options 9/10) no longer
  create a second systemd unit. They now edit the *existing* service's
  `-transport` list in place and restart that one service - no second
  process, no port conflict, failover actually works.
- `add-udp-service.sh` is now deprecated - it still exists but produces
  the same broken two-process setup described above. Use
  `setup.sh enable-udp` instead. If you already ran it (or ended up with
  a `stacktunnel-udp`/`stacktunnel-ws` service some other way), remove it:
  `systemctl disable --now stacktunnel-udp stacktunnel-ws 2>/dev/null; rm -f /etc/systemd/system/stacktunnel-udp.service /etc/systemd/system/stacktunnel-ws.service; systemctl daemon-reload`
  then use `setup.sh enable-udp`/`enable-ws` on the one remaining service.

## [0.3.2]

- Fix: `enable-udp`/`enable-ws` on the client (kharej) side built
  `-tunnel ${IRAN_IP}` straight from `config.env`, but `IRAN_IP` there was
  saved as the raw address the installer asked for - never the `:port`
  suffixed form `do_install` actually puts on the *primary* service's
  command line. Any client without an explicit port in that original
  answer (the common case) got a tunnel address with no port on the new
  sibling service, which fails outright for the udp/KCP dialer
  (`address X: missing port in address`) - the existing TCP dialer doesn't
  need a port by itself, it happened to only ever see the fully-formed
  address baked into the primary unit at install time, so this never
  surfaced before now. Fixed in two places: `do_install` now saves the
  already-port-normalized address to `config.env`, and `do_enable_transport`
  re-normalizes it defensively too, so an existing `config.env` saved
  before this fix is also covered without reinstalling.

## [0.3.1]

- Fix: `enable-udp`/`enable-ws` (and menu options 9/10) failed immediately
  with `name: unbound variable` - a `local name=... unit="...${name}..."`
  on one line expands `${name}` before that same `local` has assigned it,
  which `set -u` then rejects. Split into two statements. setup.sh only,
  no binary change.

## [0.3.0]

- Finished the third transport, `-transport ws`: a real TLS connection to a
  real domain, upgraded to a WebSocket, carrying the tunnel exactly like the
  tcp/udp transports do underneath. New flags: `-ws-host`, `-ws-port`
  (default 443), `-ws-path` (default `/`), `-ws-cert`/`-ws-key` (server,
  optional), `-ws-tls` (client, default on).
  - On the server side, `-ws-cert`/`-ws-key` are now optional, not required:
    leave both unset and the server speaks plain HTTP/WebSocket, for sitting
    behind something that already terminated TLS before forwarding here - a
    CDN edge, a load balancer, or an nginx reverse proxy inside a managed
    platform such as Google Cloud Run (which terminates TLS on its own
    public domain and forwards the decrypted WebSocket traffic on over a
    plain upstream connection). Set both to have this process terminate TLS
    itself instead, with its own certificate.
  - This is the transport to reach for as a fallback during a full
    connectivity shutdown: the TLS ClientHello is all a filter ever sees, so
    there is no opener pattern to recognize in the first place, and sharing
    a large provider's edge IPs makes outright blocking expensive. It can
    run in either direction - typically the kharej/outside server runs
    `-mode server -transport ws` in plain mode behind the CDN/proxy, and the
    Iran server runs `-mode client -transport ws -ws-host <public domain>`
    to dial out through it, the reverse of the usual TCP/UDP direction.
- `setup.sh` gained `enable-udp` and `enable-ws` (also in the interactive
  menu, options 9/10): add a second, independent transport as a parallel
  systemd service next to the primary one, without hand-writing a unit
  file. Pool/member health-scoring (0.2.3) already fails over between
  whichever services are currently connected and healthy, so this is purely
  additive resilience - nothing about the primary service changes. This
  replaces the standalone `add-udp-service.sh` script for the UDP case
  (still present and still works, but the setup.sh command is the
  supported path going forward) and extends the same idea to `ws`.
- `do_status` now also prints a short status block for every
  `stacktunnel-*` sibling service it finds, so one command shows all
  active transports at once.

## [0.2.3]

- The server's port-forwarding no longer picks a member tunnel with plain
  round-robin alone: each member now tracks a lightweight health score
  (consecutive stream open/write failures), and `pick()` prefers whichever
  currently-connected members have the fewest recent failures, falling
  back to round-robin among equally-healthy ones. A member that starts
  failing (one path in a multi-transport or multi-server setup degrading)
  is steered away from automatically without being dropped from the pool -
  it keeps getting tried again and recovers on its own once it succeeds
  again, or once every other member is in the same shape. No flags, no
  wire changes; purely server-side.

## [0.2.2]

- Fixed: the UDP transport's KCP layer was sending its own packet header
  (connection id, serial numbers, timestamps) in clear. That header is a
  well-known, publicly documented byte pattern on its own - some DPI
  systems match raw KCP traffic by it regardless of what is encrypted
  inside. Every KCP packet is now itself encrypted with a key derived from
  the pre-shared key, so the header is no longer visible on the wire. This
  is on top of, not instead of, the existing per-connection encryption of
  the actual tunnel data. **Not wire-compatible with 0.2.1's UDP transport**
  (TCP transport is unaffected) - update both sides together if you use
  `-transport udp`.

## [0.2.1]

- Added a second transport, `-transport udp` (default stays `tcp`): instead
  of the fake SSH banner over TCP, the client sends one raw STUN Binding
  Request datagram first (satisfying the filter's UDP exemption), then all
  further traffic is KCP with Reed-Solomon forward error correction
  (`-fec-data`/`-fec-parity`) on the same local port. Everything above the
  transport - the handshake, encryption, yamux multiplexing, rotation,
  source-IP rotation - is unchanged and works the same way under either
  transport. Both sides must use the same `-transport` value.

## [0.2.0]

- Replaced the handshake's key agreement with a real X25519 ECDH exchange.
  Previously, session keys were derived from the pre-shared key and two
  random values alone, with no actual Diffie-Hellman step, so a leaked PSK
  could retroactively decrypt any captured traffic. Each connection now
  generates a fresh ephemeral X25519 keypair, performs a real ECDH, and
  derives keys from PSK + the ECDH shared secret + both public keys, giving
  genuine forward secrecy: a leaked PSK no longer exposes past sessions.
  The wire format is unchanged (same 32-byte field inside the fake SSH
  KEX_ECDH_INIT/REPLY messages), but the derived keys differ, so this is
  **not wire-compatible with 0.1.x** - update both the inside and outside
  server at the same time.

## [0.1.4]

- Added frame-size randomization (`-fragment`, on by default): instead of always filling a frame
  to the maximum size, each frame's length is picked randomly, so application write boundaries
  are no longer visible as fixed-size frames on the wire.
- Added decoy frames (`-junk DURATION`, e.g. `-junk 20s`, default off): both sides can send
  content-free frames on a jittered timer to add timing/size noise independent of real traffic.
  The receiver already silently discards any frame with zero real length, so this needed no
  protocol change. Wire-compatible with 0.1.x (older binaries simply never see junk frames
  from a newer peer unless the newer peer has `-junk` set, and always tolerate them either way).
- Added IPv6-aware source-IP rotation (`-source-ips`), from the previous working session.

## [0.1.3]

- Fix: on some paths a tunnel connection would be throttled hard (collapsed send window,
  growing retransmit timeout) after roughly 10-16 minutes, then recover after reconnecting.
  The client now proactively replaces each tunnel connection on a jittered timer before that
  happens (`-rotate`, default `5m`, `0` disables), opening the replacement first and draining
  the old one instead of cutting it, so in-flight transfers are not interrupted.
- The yamux keepalive interval is now randomized per connection (12-20s) instead of a fixed
  15s for every connection, which was itself a recognisable pattern. Wire-compatible with 0.1.x.
  `setup.sh install` now asks for the rotation interval on the kharej side.

## [0.1.2]

- Clearer logs on the inside server: failed handshakes, wrong keys and silent connections are now
  logged with the reason, `tunnel up` lists the announced ports, `tunnel down` shows how long the
  tunnel lasted, and a dropped user connection says which tunnels and ports are currently connected.
  Wire-compatible with 0.1.x.

## [0.1.1]

- Fix: on slow or congested links the tunnel could stall for many seconds and drop connections
  under load. The per-stream window default is now 1 MB (was 8 MB) and the keepalive timeout is
  60 s (was 20 s). New flag `-window` (in KB) to tune it. Wire-compatible with 0.1.0.
- New speed test that measures the real path between your servers with several window sizes and
  recommends one: `sudo bash setup.sh tune` (and `sudo bash setup.sh window <KB>` to apply it).

## [0.1.0]

First public release, under the PolyForm Noncommercial License 1.0.0.

- Reverse TCP and UDP tunnel with a shared key
- Several parallel tunnel connections, automatic reconnect, keepalive
- Port ranges, several outside servers per inside server, several inside servers per outside server
- Optional random padding (`-pad`)
- `-bind`, `-conns`, `-version` flags and clearer log messages
- Interactive installer `setup.sh` (systemd service, `ufw`, update command)
- Binaries for Linux (amd64, arm64, armv7), Android (arm64), macOS, Windows and FreeBSD
