# تحلیل باینری libxray.so — 2026-11-28

## خلاصه

فایل ارائه‌شده با نام `libxray.so` یک باینری Go برای Android/ARM64 است. با وجود پسوند `.so`، metadata ساخت آن صریحاً `-buildmode=exe` را نشان می‌دهد؛ فایل دارای interpreter اندروید، نقطه ورود `_start` و تابع `main.main` است. بنابراین از نظر ELF یک PIE executable است، نه یک shared library معمولی برای `dlopen` یا `System.loadLibrary`.

**SHA-256:** `e796e24eece84ab28ab9e20710a8581fbcb1044c6720db5f9c79fecc839f68b5`

**حجم:** 32,740,552 bytes

## مشخصات ELF

| ویژگی | مقدار |
|---|---|
| ELF | 64-bit, little-endian |
| نوع | ET_DYN / PIE executable |
| معماری | AArch64 |
| سیستم‌عامل هدف | Android |
| حداقل API ثبت‌شده | Android 21 |
| Go | go1.26.2 |
| Build mode | exe |
| Interpreter | `/system/bin/linker64` |
| Dynamic dependencies | `liblog.so`, `libdl.so`, `libc.so` |
| ELF stripped | بله؛ اما `.gopclntab` حفظ شده است |

در جدول نمادهای پویا 123 نماد وجود دارد. `_start`، `main` و `main.main` دیده می‌شوند؛ `JNI_OnLoad` و نمادهای `Java_*` مشاهده نشدند. این شواهد با اجرای باینری به‌عنوان پردازه سازگار است، اما مسیر واقعی اجرای آن باید از DEX/Java و لاگ runtime تأیید شود.

## منشأ و metadata ساخت

- module path: `github.com/xtls/xray-core/main`
- module version: `(devel)`
- Go build version: `go1.26.2`
- VCS revision ثبت‌شده: `9bfe7230e9c17f76afbb905e0726f553559892a4`
- VCS time ثبت‌شده: `2020-10-19T02:07:38Z`
- `vcs.modified=true`
- build flags شامل `-ldflags="-s -w"` و `CGO_ENABLED=1`

زمان VCS ثبت‌شده با نسخه‌های جدید وابستگی‌ها و Go سازگاری زمانی روشنی ندارد؛ بنابراین revision/time را نباید بدون تطبیق با source repository به‌عنوان نسخه قطعی Xray معرفی کرد. عبارت `(devel)` نیز نسخه release مشخصی ارائه نمی‌دهد.

## کدها و پروتکل‌های کامپایل‌شده

بازیابی آفلاین نام توابع از Go pclntab مسیرهای زیر را در باینری نشان داد:

| دسته | مسیرهای کد مشاهده‌شده |
|---|---|
| Proxy protocols | VLESS، VMess، Trojan، Shadowsocks، Shadowsocks 2022، Hysteria، WireGuard، SOCKS، HTTP |
| Built-in handlers | freedom، blackhole، DNS، dokodemo، loopback، TUN |
| Transports | TCP، TLS، REALITY، WebSocket، gRPC، HTTP Upgrade، SplitHTTP/XHTTP، KCP، UDP، Hysteria |
| Tunnel/network stack | Xray TUN، AndroidTun، gVisor network stack |

نمونه‌های مشخص از نام توابع بازیابی‌شده:
- `proxy/vless/encryption.(*ClientInstance).Handshake`
- `proxy/vmess/aead.SealVMessAEADHeader`
- `proxy/trojan.NewClient`
- `proxy/shadowsocks.NewClient`
- `proxy/shadowsocks_2022` account/config handlers
- `proxy/wireguard` و `proxy/wireguard/gvisortun`
- `proxy/tun.(*AndroidTun).Start` و `Close`
- `transport/internet/reality`
- `transport/internet/splithttp`

وابستگی‌های مهم ثبت‌شده در Go build info:
- `github.com/apernet/quic-go` نسخه `v0.59.1-0.20260330051153-c402ee641eb6`
- `github.com/xtls/reality` نسخه `v0.0.0-20260322125925-9234c772ba8f`
- `github.com/refraction-networking/utls` نسخه `v1.8.3-0.20260301010127-aa6edf4b11af`
- `github.com/sagernet/sing` نسخه `v0.5.1`
- `github.com/sagernet/sing-shadowsocks` نسخه `v0.2.7`
- `gvisor.dev/gvisor` نسخه ثبت‌شده در build info

این شواهد وجود کد و وابستگی‌ها را ثابت می‌کنند، نه فعال بودن همه قابلیت‌ها در UI یا موفقیت اتصال زنده. برای Hysteria نیز از این تحلیل به‌تنهایی نباید نسخه یا سازگاری Hysteria2 نتیجه گرفت.

## CLI و نحوه میزبانی

رشته‌ها و نمادهای اجرایی وجود CLI را تأیید می‌کنند:
- متن help: «Run Xray with config, the default command.»
- گزینه‌های `-config/-c`، `-confdir`، `-format`، `-test` و `-dump`
- تابع `main.main` و command framework در `main/commands/base`

این یافته همراه با `-buildmode=exe` فرضیه اجرای process جداگانه را تقویت می‌کند. هنوز مشخص نیست فایل دقیقاً با چه نام/مسیر و چه آرگومان‌هایی از APK اجرا می‌شود، config چگونه ساخته می‌شود، یا TUN file descriptor چگونه به آن می‌رسد.

## بازیابی Go pclntab و اصلاح parser

بخش `.gopclntab` در این فایل حفظ شده است. header شامل 39,856 تابع و 2,574 فایل است. بررسی آفلاین با قواعد فرمت Go 1.18+ توانست **39,856 رکورد تابع** را بازیابی کند.

این بررسی روی باینری واقعی دو فرض نادرست parser قبلی را آشکار کرد:
1. `funcOff` در functab نسبت به ابتدای `pcln` table است، نه ابتدای فایل ELF یا ابتدای pclntab.
2. در این PIE مقدار header field مربوط به `textStart` صفر است؛ برای اعتبارسنجی entry PC باید base متن از یک `.text` اجرایی یکتا در section table حل شود.

ابزار `tools/recover_go_pclntab.py` و fixtureهای تست در همین branch برای این دو حالت اصلاح شده‌اند. الگوریتم اصلاح‌شده روی فایل واقعی 39,856 رکورد را با نام تابع بازیابی کرد. با این حال، pytest مربوط به branch پس از این اصلاحات هنوز اجرا نشده و باید پیش از ادعای pass شدن تست‌ها اجرا شود.

## نتیجه برای مهندسی معکوس ApnaWin

1. وجود یک موتور Xray مبتنی بر کد `xtls/xray-core` در فایل اثبات شد.
2. پسوند `.so` گمراه‌کننده است؛ ساخت ثبت‌شده executable است. مسیر فراخوانی را باید در DEX و کد Java/Kotlin با جست‌وجوی `ProcessBuilder`، `Runtime.exec`، مسیر فایل و آرگومان‌های CLI دنبال کرد.
3. مسیر Android TUN در کد موجود است، ولی اتصال آن به VPNService/FD اپ هنوز اثبات نشده است.
4. پروتکل‌های Xray را از پروتکل اختصاصی APNA و از موتورهای جداگانه `libudpqtwo.so` و `libsalamander.so` تفکیک نگه دارید.
5. هیچ‌کدام از این یافته‌ها ثابت نمی‌کند که همه پروتکل‌ها از UI قابل انتخاب‌اند یا اتصال واقعی برقرار می‌شود.

## کارهای بعدی

- جست‌وجوی APK-wide در DEX برای نام فایل `libxray.so`، مسیر استخراج، chmod، `execve`/ProcessBuilder و آرگومان‌های `-config`.
- ردیابی تولید/انتقال config و schema واقعی مورد استفاده اپ؛ مقایسه با schema همین build.
- ردیابی Android VPNService و تحویل TUN FD به Xray.
- اجرای pytest برای parser اصلاح‌شده و سپس استفاده از آن روی `libudpqtwo.so` پس از دریافت باینری واقعی.
- حفظ hash و ABI provenance؛ باینری خام در Git commit نشود.

## محدودیت‌ها

این تحلیل ایستا و آفلاین بوده است. باینری اجرا نشده، به شبکه وصل نشده، هیچ config یا credential آزمایش نشده و رفتار runtime از روی حدس تکمیل نشده است.
