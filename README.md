<div dir="rtl">

# VPN Share | اشتراک اینترنت VPN

**اینترنت VPN کامپیوتر را از طریق وای‌فای یا کابل شبکه به دستگاه‌های دیگر برسانید.**

VPN Share یک ابزار دسکتاپ با ظاهر ویجتی است. اتصال VPN موجود را شناسایی می‌کند و امکان اشتراک آن را فراهم می‌کند؛ دستگاه مهمان فقط به شبکه خروجی متصل می‌شود و به برنامه VPN یا تنظیم پروکسی نیاز ندارد.

**نسخه فعلی: `0.5.0-preview.2` — پیش‌نمایش**

[English](README.en.md) · [دانلود نسخه‌ها](https://github.com/navidhaghpanah/vpn-share/releases/tag/v0.5.0-preview.2) · [راهنمای فارسی](wiki/Home.md) · [GitHub Wiki](https://github.com/navidhaghpanah/vpn-share/wiki)

## دانلود

| سیستم‌عامل | فایل | وضعیت |
| --- | --- | --- |
| Windows 10 نسخه 2004 به بعد / Windows 11، معماری x64 | [فایل EXE پرتابل](https://github.com/navidhaghpanah/vpn-share/releases/download/v0.5.0-preview.2/VPNShare-0.5.0-preview.2.exe) | ساخت و تست خودکار موفق؛ اشتراک واقعی روی Windows 11 مشاهده شده است |
| Ubuntu / Debian با محیط دسکتاپ | [بسته DEB](https://github.com/navidhaghpanah/vpn-share/releases/download/v0.5.0-preview.2/vpnshare_0.5.0.preview2_all.deb) | ساخت بسته و تست منطقی موفق؛ هات‌اسپات روی سخت‌افزار لینوکس هنوز تأیید نشده است |
| کد منبع | [Source ZIP](https://github.com/navidhaghpanah/vpn-share/releases/download/v0.5.0-preview.2/VPNShare-0.5.0-preview.2-source.zip) | شامل سورس Windows و Linux |

[فایل SHA256SUMS.txt](https://github.com/navidhaghpanah/vpn-share/releases/download/v0.5.0-preview.2/SHA256SUMS.txt) برای بررسی صحت دانلود منتشر شده است.

## شروع سریع در ویندوز

1. اینترنت ورودی کامپیوتر را برقرار کنید؛ ورودی می‌تواند Wi-Fi، Ethernet یا USB tethering گوشی باشد.
2. VPN کامپیوتر را وصل کنید و از کارکرد اینترنت آن مطمئن شوید.
3. فایل EXE را اجرا و درخواست دسترسی Administrator را تأیید کنید. نصب جداگانه .NET لازم نیست.
4. VPN موردنظر را از فهرست انتخاب کنید.
5. برای هات‌اسپات، **Wi-Fi hotspot** را انتخاب و نام شبکه و رمز را تعیین کنید. برای کابل، **Ethernet** و کارت خروجی آزاد را انتخاب کنید.
6. **Start sharing** را بزنید؛ دستگاه مهمان را به شبکه خروجی وصل کنید.
7. برای پایان اشتراک، **Stop sharing** را بزنید و اجازه دهید بازیابی تنظیمات کامل شود.

برنامه در ویندوز از NAT اختصاصی و درایور جداگانه Windows Packet Filter استفاده می‌کند. اگر درایور موجود نباشد، برنامه نصب‌کننده رسمی را دریافت و هش و امضای آن را بررسی می‌کند. **فایل برنامه پرتابل است، ولی نصب درایور به دسترسی سیستمی نیاز دارد.** فایل درایور داخل دانلود پروژه بازتوزیع نشده است.

## امکانات

- شناسایی VPN موجود و اشتراک از طریق وای‌فای یا Ethernet آزاد.
- تنظیم نام شبکه و رمز هات‌اسپات داخل برنامه.
- پشتیبانی از اینترنت ورودی LAN، Wi-Fi و USB tethering.
- انتخاب کارت خروجی وای‌فای در Options، با محدودیت‌های واقعی درایور و Windows.
- نمایش تعداد مشتریان و حجم ترافیک، کوچک‌شدن در System Tray و بخش About.
- در Linux: رابط GTK، مدیریت هات‌اسپات با NetworkManager و مسیریابی با nftables.

داشتن چند کارت شبکه به‌تنهایی کافی نیست: کارت خروجی باید حالت AP سازگار داشته باشد و کارت ورودی نباید با خروجی اشتباه انتخاب شود. جزئیات در [راهنمای کارت‌های شبکه](wiki/Sharing-and-Adapters.md) آمده است.

## نصب در Ubuntu / Debian

در پوشه فایل دانلودشده اجرا کنید:

```bash
sudo apt install ./vpnshare_0.5.0.preview2_all.deb
```

سپس VPN Share را از منوی برنامه‌ها باز کنید. رابط را با کاربر عادی اجرا کنید؛ عملیات شبکه از طریق helper و تأیید polkit انجام می‌شود. [راهنمای کامل Linux](wiki/Installation-Linux.md)

## وضعیت تست و محدودیت‌ها

در GitHub Actions، **۷۵ بررسی Windows و ۳۶ تست Linux** موفق بوده‌اند. ساخت EXE و DEB و انتشار Preview 2 نیز موفق بوده است. فایل‌های عمومی دانلود و SHA-256 آن‌ها بررسی شده‌اند.

در تست سخت‌افزاری Windows 11، یک دستگاه مستقل به هات‌اسپات وصل شد، IP گرفت و با دیتای موبایل خاموش از VPN استفاده کرد. این نتیجه تضمین سازگاری با تمام VPNها و کارت‌های وای‌فای نیست.

**موارد هنوز تأییدنشده:** تست کامل قطع و اتصال مجدد VPN، نشت DNS/IPv6 روی دستگاه مهمان، بازیابی پس از crash، بازیابی واقعی اصلاح‌شده در Preview 2، Windows 10 و هات‌اسپات واقعی Linux. بنابراین این نسخه گواهی تکمیل تست امنیتی یا End-to-End نیست. [جزئیات امنیت و تست](wiki/Security-and-Testing.md)

## راهنما و پشتیبانی

- [فهرست راهنمای فارسی](wiki/Home.md)
- [نصب Windows](wiki/Installation-Windows.md) · [نصب Linux](wiki/Installation-Linux.md)
- [انتخاب کارت شبکه](wiki/Sharing-and-Adapters.md) · [رفع خطا و Restore network](wiki/Troubleshooting.md)
- [سؤال‌های متداول](wiki/FAQ.md) · [ساخت از سورس](wiki/Development.md)
- [ثبت مشکل](https://github.com/navidhaghpanah/vpn-share/issues)

در گزارش عمومی، رمز وای‌فای، اطلاعات حساب VPN، آدرس‌ها و شناسه‌های خصوصی دستگاه را حذف کنید.

## توسعه‌دهنده

**NH / Navid Haghbayan**  
وب‌سایت: [sirgsm.ir](https://sirgsm.ir) · تلگرام: [@nhaghbayan](https://t.me/nhaghbayan) · تلفن: `09338140808`

مجوز کد پروژه در [LICENSE](LICENSE) است. درایور Windows Packet Filter مجوز مستقل دارد؛ شرایط استفاده شخصی و تجاری را در [وب‌سایت سازنده](https://www.ntkernel.com/windows-packet-filter/licensing/) بررسی کنید.

</div>
