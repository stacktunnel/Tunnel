# Changelog

This project uses [Semantic Versioning](https://semver.org). While the major version is `0`,
a change in the **minor** number (`0.1.x` → `0.2.0`) may break compatibility between servers,
so update the inside and the outside server together. Patch releases (`0.1.0` → `0.1.1`) are
compatible with each other.

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
