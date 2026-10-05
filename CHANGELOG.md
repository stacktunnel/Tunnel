# Changelog

This project uses [Semantic Versioning](https://semver.org). While the major version is `0`,
a change in the **minor** number (`0.1.x` → `0.2.0`) may break compatibility between servers,
so update the inside and the outside server together. Patch releases (`0.1.0` → `0.1.1`) are
compatible with each other.

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
