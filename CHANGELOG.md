# Changelog

This project uses [Semantic Versioning](https://semver.org). While the major version is `0`,
a change in the **minor** number (`0.1.x` → `0.2.0`) may break compatibility between servers,
so update the inside and the outside server together. Patch releases (`0.1.0` → `0.1.1`) are
compatible with each other.

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
