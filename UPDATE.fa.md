# نصب نسخهٔ اصلاح‌شده از سورس

این بسته بر اساس کامیت `44fb90990bdee9d7a4c14322d0150a096bd03a60` ساخته شده است.
تمام فایل‌های سورس مخزن را دارد؛ نیازی به اعمال patch نیست. فایل‌های داخل پوشهٔ
`Tunnel` را روی checkout خودت کپی کن، تغییرات را بررسی کن و خودت commit/push کن.

این نسخه مهلت handshake و بازیابی اتصال را اصلاح می‌کند. حذف بسته‌های شبکه را
رفع نمی‌کند و SSH واقعی اضافه نمی‌کند. از نظر پروتکل با نسخهٔ 0.1.1 سازگار است.

## ساخت

داخل پوشهٔ سورس با Go نسخهٔ 1.18 یا بالاتر اجرا کن:

```bash
go test ./... &&
go build -trimpath -ldflags '-s -w -X main.version=v0.1.1-handshake-fix' -o stacktunnel-fixed .
```

برای تست race روی محیط دارای C compiler: `go test -race ./...`.

## نصب روی سرور موجود

ابتدا روی کلاینت خارجِ مشکل‌دار نصب کن. این دستور سرویس همان سرور را restart می‌کند
و اتصال‌های آن قطع می‌شوند. برای نصب روی ایران، زمان مناسب قطع سرویس همهٔ کلاینت‌ها
را انتخاب کن. تنظیمات موجود سرویس حفظ می‌شوند.

```bash
backup="/usr/local/bin/stacktunnel.backup.$(date +%Y%m%d-%H%M%S)"
sudo cp -a /usr/local/bin/stacktunnel "$backup" &&
sudo install -m 0755 stacktunnel-fixed /usr/local/bin/stacktunnel.new &&
sudo mv /usr/local/bin/stacktunnel.new /usr/local/bin/stacktunnel &&
sudo systemctl restart stacktunnel
printf 'Backup: %s\n' "$backup"
sudo journalctl -u stacktunnel -n 50 --no-pager
```

برای بازگشت، فایل backup مشخص‌شده را به جای باینری نصب کن و سرویس را restart کن.
تا وقتی release تازه منتشر نکرده‌ای، `setup.sh update` را اجرا نکن؛ آن دستور
آخرین release منتشرشده را دانلود می‌کند، نه سورس جدید main را.

## تنظیمات جدید

- `-handshake-timeout 20s`: مهلت کل handshake؛ مقدار مثبت لازم است.
- `-debug`: نمایش خطاهای داخلی Yamux در stderr/journal.
- خطاهای handshake مرحله و آدرس socket را دارند؛ خطاهای سمت سرور محدودسازی نرخ دارند.
- کلاینت فقط `-conns 1` تا `-conns 32` را قبول می‌کند.

مهلت پیش‌فرض بدون تغییر فایل سرویس اعمال می‌شود. اگر لازم شد این پرچم‌ها را به
ExecStart سرویس اضافه کنی، پس از ویرایش `systemctl daemon-reload` و restart لازم است.

## محدودیت تشخیص

تست‌ها محلی‌اند؛ هیچ تغییری از این بسته روی سرورهای واقعی نصب نشده است.
تست SSH واقعی بین سرورها هنوز انجام نشده و نیاز به دسترسی به همان سرورها دارد.
تغییر نوع transport، بازطراحی رمزنگاری و رفع محدودیت شبکه جزو این اصلاح نیست.
