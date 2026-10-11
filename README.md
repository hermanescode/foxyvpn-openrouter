# FoxyVPN OpenRouter

<p align="center">
  <strong>کلاینت مستقل و سبک فایرفاکس VPN برای پلتفرم روتر OpenWrt با پنل مدیریت تحت وب و پروکسی اختصاصی SOCKS5</strong>
  <br />
  <em>Unofficial Firefox VPN client for OpenWrt routers with a built-in Web Dashboard & local SOCKS5 proxy server.</em>
</p>

---

## 🌟 ویژگی‌ها (Key Features)

- 🚀 **پورت شده به زبان Go**: کامپایل تک‌فایلی (Single Static Binary)، فوق‌العاده سبک، مصرف ناچیز رم و پردازنده، کاملاً سازگار با محدودیت‌های روتر.
- 🦊 **پشتیبانی کامل از سهمیه رایگان ۵۰ گیگابایت موزیلا (50GB Free Firefox VPN)**: بدون نیاز به اشتراک پولی، اتصال از طریق اکانت رایگان فایرفاکس.
- 🧦 **پروکسی SOCKS5 اختصاصی**: بدون هدایت اجباری تمام ترافیک روتر؛ ارائه‌دهنده پورت ساکس (مثلاً `0.0.0.0:1080`) برای اتصال اختیاری مرورگرها، تلگرام یا کلاینت‌های شبکه محلی (LAN).
- 🎨 **داشبورد وب مینیمال و مدرن (Embedded Web UI)**:
  - لاگین مستقیم با حساب فایرفاکس (FxA) و فعال‌سازی خودکار در Mozilla Guardian.
  - دکمه اتصال/قطع (Connect / Disconnect) تک‌کلیکه.
  - نمایش زنده سهمیه ۵۰ گیگابایت ماهانه (میزان مصرف، باقیمانده و تاریخ بازنشانی).
  - مانیتورینگ زنده پینگ و پایش وضعیت خروجی سرور و آدرس IP خروجی (Fastly Edge CDN).
  - انتخاب حالت خودکار (پایین‌ترین پینگ / Fastest Edge) یا انتخاب دستی کشور و شهر.
  - کنسول زنده لاگ‌ها (Live Logs).
  - امکان قفل‌گذاری روی پنل با رمز عبور.
- 🔄 **اتصال مجدد خودکار (Auto-Reconnect) و سوئیچ سرور (Auto-Failover)**: در صورت بروز اختلال یا قطعی، سیستم به شکل خودکار سرور بعدی یا با پینگ کمتر را جایگزین می‌کند.
- 🎯 **سازگار با روترهای OpenWrt**: بهینه‌سازی شده برای معماری‌های مختلف، به ویژه روتر **Google Wifi AC1304 (پردازنده چهار هسته‌ای Qualcomm IPQ4019 / ARMv7-A Cortex-A7)**.
- ⚙️ **سرویس استاندارد Procd OpenWrt**: همراه با فایل‌های راه‌اندازی `/etc/init.d/foxyvpn` و اجرای خودکار در بوت دستگاه.

---

## 🏗 ساختار پروژه (Architecture)

```
foxyvpn-openrouter/
├── cmd/
│   └── foxyvpn/             # نقطه ورود برنامه (Main CLI & Server)
├── pkg/
│   ├── config/              # مدیریت تنظیمات JSON و تمدید خودکار سشن
│   ├── core/                # پروتکل‌های هسته موزیلا (FxA Auth, Guardian, Fastly H2)
│   ├── vpn/                 # مدیریت نشست‌های تونل، سوئیچ سرور و سرور SOCKS5
│   └── web/                 # وب‌سرور و رابط کاربری تعبیه‌شده (HTML/CSS/JS)
├── openwrt/
│   ├── etc/init.d/foxyvpn   # اسکریپت اجرای Procd در OpenWrt
│   ├── etc/config/foxyvpn   # پیکربندی اولیه
│   └── install.sh           # اسکریپت نصب یک‌خطی خودکار
├── .github/workflows/       # فرآیند بیلد خودکار چندمعماری (CI/CD Releases)
└── Makefile                 # دستورات ساخت و کراس‌کامپایل
```

---

## 🚀 راهنمای نصب سریع روی OpenWrt (Quick Start)

### روش اول: اجرای اسکریپت نصب خودکار روی روتر

کافیست از طریق SSH به روتر خود متصل شوید و دستور زیر را اجرا نمایید:

```sh
sh -c "$(wget -O- https://raw.githubusercontent.com/hermanescode/foxyvpn-openrouter/main/openwrt/install.sh)"
```

اسکریپت به صورت خودکار معماری روتر شما (مثلاً `ARMv7` برای Google Wifi AC1304) را تشخیص داده، فایل باینری را دانلود و سرویس را فعال می‌کند.

---

### روش دوم: نصب و راه‌اندازی دستی

#### ۱. دانلود یا بیلد فایل باینری مناسب روتر

اگر روتر شما **Google Wifi AC1304** است:
```bash
# بیلد برای Google Wifi AC1304 (ARMv7-A Cortex-A7)
make build-linux-armv7
```
فایل تولید شده در مسیر `dist/foxyvpn-linux-armv7` قرار می‌گیرد.

#### ۲. انتقال باینری به روتر

فایل را از طریق `scp` به روتر منتقل کنید:
```bash
scp dist/foxyvpn-linux-armv7 root@192.168.1.1:/usr/bin/foxyvpn
```

#### ۳. تنظیم دسترسی و سرویس در روتر

وارد SSH روتر شوید:
```sh
chmod +x /usr/bin/foxyvpn

# کپی اسکریپت سرویس OpenWrt
cat << 'EOF' > /etc/init.d/foxyvpn
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

PROG=/usr/bin/foxyvpn
CONF=/etc/foxyvpn/config.json

start_service() {
    [ -x "$PROG" ] || return 1
    mkdir -p /etc/foxyvpn

    procd_open_instance
    procd_set_param command "$PROG" -config "$CONF"
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    killall foxyvpn 2>/dev/null
}
EOF

chmod +x /etc/init.d/foxyvpn
/etc/init.d/foxyvpn enable
/etc/init.d/foxyvpn start
```

---

## 🖥 دسترسی به پنل تحت وب (Web Dashboard)

پس از اجرای سرویس، پنل وب روی آدرس زیر در دسترس است:

👉 `http://192.168.1.1:8080` *(آدرس IP روتر خود را جایگزین کنید)*

در پنل وب می‌توانید:
1. ایمیل و پسورد اکانت فایرفاکس خود را وارد کرده و لاگین کنید.
2. وضعیت سهمیه ۵۰ گیگابایت، پینگ و وضعیت اتصال را مشاهده نمایید.
3. با فشردن دکمه **Connect**، پروکسی را فعال کنید.

---

## 🔌 نحوه استفاده از پروکسی SOCKS5 در دستگاه‌ها

پروکسی ساکس به صورت پیش‌فرض روی تمام اینترفیس‌های روتر با آدرس زیر گوش می‌دهد:

```
Host: 192.168.1.1  (یا IP روتر شما)
Port: 1080
Type: SOCKS5
```

### تست سریع با cURL:
```bash
curl -x socks5h://192.168.1.1:1080 https://ipinfo.io
```

### تنظیم در تلگرام (Telegram):
- **Settings** -> **Data and Storage** -> **Proxy Settings** -> **Add Proxy**
- انتخاب **SOCKS5 Proxy**
- Server: `192.168.1.1`
- Port: `1080`

### تنظیم در فایرفاکس / کروم:
در بخش Network Proxy مرورگر خود یا اکستنشن‌هایی مانند SwitchyOmega:
- پروتکل: **SOCKS Host** -> `192.168.1.1`
- پورت: `1080`
- فعال‌سازی گزینه: **Proxy DNS when using SOCKS v5**

---

## 🛠 پارامترهای خط فرمان (CLI Flags)

```
Usage of foxyvpn:
  -config string
        Path to config file (default: /etc/foxyvpn/config.json)
  -web string
        Web UI listen address (default: :8080)
  -socks string
        SOCKS5 listen address (default: 0.0.0.0:1080)
  -version
        Print version and exit
```

---

## 📜 لایسنس (License)

این پروژه تحت لایسنس MIT منتشر شده است.
این ابزار یک پروژه متن‌باز غیررسمی بوده و به موزیلا یا فاستلی وابسته نیست.
