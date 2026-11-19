# StackTunnel Panel

[فارسی پایین‌تر](#فارسی)

A web panel for running StackTunnel on one inside (Iran) server and several outside servers:

- **Dashboard**: which kind of outage you are in, a live map of what connects to what, reachability between all servers.
- **Tunnels & ports**: every outside server next to its inside service; add or remove a TCP/UDP port and the inside side is updated too; edit every flag, start/stop/restart, logs, backups and restore; create a new tunnel.
- **Speed test**: raw path between servers, and through the tunnel itself (shows when a path dies after a few KB).
- **Best settings**: tries `conns` × `window` × `transport` on a separate test tunnel (users are not touched), ranks the results and recommends the smallest window that reaches 90% of the best speed — same rule as `setup.sh tune`; one click applies it (window on both sides).

Every change is previewed as a diff, the previous unit is backed up, and if the service does not stay up the change is rolled back automatically.

## Install

Inside server (panel + its own agent):

```bash
curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel/install.sh | sudo bash -s -- panel
curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel/install.sh | sudo bash -s -- agent --name iran --role iran
```

Each outside server (allow only the inside server's IP):

```bash
curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel/install.sh | sudo bash -s -- agent --name hz1 --role kharej --allow INSIDE_IP
```

It prints an address, token and fingerprint: add them in the panel under **Servers → Add server**.

Open the panel through SSH (it only listens on 127.0.0.1):

```bash
ssh -L 8480:127.0.0.1:8480 root@INSIDE_SERVER     # then open http://127.0.0.1:8480
```

Update / remove (on any server):

```bash
curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel/install.sh | sudo bash -s -- update
curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel/install.sh | sudo bash -s -- uninstall
```

Needs only `python3`, `openssl`, `iproute2`. The agent talks TLS with a pinned certificate, a token, and a normal-looking SNI (some routes reset bare-IP TLS). It only edits `stacktunnel*.service` units, with a fixed list of allowed flags. On Oracle Linux / RHEL the installer also opens the agent port in firewalld.

---

## فارسی

پنل وب برای مدیریت StackTunnel روی یک سرور ایران و چند سرور خارج: داشبورد و نوع قطعی، نقشه‌ی اتصال‌ها، افزودن/حذف پورت برای هر سرور خارج (سمت ایران خودکار هماهنگ می‌شود)، ویرایش همه‌ی تنظیمات، لاگ، بکاپ و برگرداندن، تست سرعت، و **پیدا کردن بهترین تنظیمات** (conns × window × transport روی یک تانل تستی جدا، بدون دست زدن به کاربرها).

هر تغییر اول به‌صورت diff نشان داده می‌شود، از نسخه‌ی قبلی بکاپ گرفته می‌شود و اگر سرویس بالا نیاید، خودکار برمی‌گردد.

نصب روی سرور ایران:

```bash
curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel/install.sh | sudo bash -s -- panel
curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel/install.sh | sudo bash -s -- agent --name iran --role iran
```

روی هر سرور خارج:

```bash
curl -fsSL https://raw.githubusercontent.com/stacktunnel/Tunnel/main/panel/install.sh | sudo bash -s -- agent --name hz1 --role kharej --allow IP_IRAN
```

خروجی (آدرس، token، fingerprint) را در پنل، تب «سرورها ← افزودن سرور» وارد کنید. باز کردن پنل: `ssh -L 8480:127.0.0.1:8480 root@SERVER_IRAN` و بعد `http://127.0.0.1:8480`.

آپدیت: همان لینک با `update`. حذف: با `uninstall`.
