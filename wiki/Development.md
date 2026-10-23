<div dir="rtl">

# ساخت از سورس و توسعه

## ساختار مخزن

| مسیر | کاربرد |
| --- | --- |
| `Windows/` | ویجت WinForms، NAT، درایور، DHCP/DNS و بازیابی |
| `Windows/Tests/` | بررسی‌های پروتکل و رگرسیون Windows |
| `Linux/` | رابط GTK، helper، منطق شبکه و تست‌های Linux |
| `tools/build_deb.py` | ساخت DEB بدون نصب روی میزبان build |
| `wiki/` | منبع راهنمای فارسی و فایل‌های GitHub Wiki |
| `.github/workflows/` | ساخت، انتشار و همگام‌سازی مستندات |

## دریافت سورس

```bash
git clone https://github.com/navidhaghpanah/vpn-share.git
cd vpn-share
```

## Windows

برای build به Windows و .NET SDK 8 نیاز دارید. اجرای تست‌های زیر تنظیمات شبکه را تغییر نمی‌دهد:

```powershell
dotnet run --project Windows/Tests/Tests.csproj -c Release
dotnet publish Windows/VpnShare.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o artifacts/windows
```

اجرای عملی برنامه و عملیات شبکه به دسترسی Administrator و درایور جداگانه نیاز دارد. نصب‌کننده یا فایل درایور شخص ثالث را بدون مجوز بازتوزیع به مخزن یا Release اضافه نکنید.

## Linux

تست‌های منطقی با Python قابل اجرا هستند؛ اجرای رابط به GTK/PyGObject و عملیات شبکه به وابستگی‌های توزیع نیاز دارد:

```bash
python3 -m unittest discover -s Linux
python3 -m py_compile Linux/widget.py
python3 tools/build_deb.py
```

بسته در مسیر `outputs/VPNShare-Linux/` ساخته می‌شود. نام داخلی فایل تولیدشده از `~` برای نسخه Debian استفاده می‌کند؛ نام فایل در GitHub Release با نقطه منتشر شده است. این تفاوت نام فایل، نسخه داخل بسته را تغییر نمی‌دهد.

## تغییر مستندات

متن فارسی را در `wiki/*.md` و `README.md` و متن انگلیسی را در `README.en.md` ویرایش کنید. لینک‌های داخلی صفحات راهنما با پسوند `.md` در مخزن معتبرند؛ workflow همگام‌سازی، آن‌ها را برای GitHub Wiki تبدیل می‌کند. برای ایجاد اولین Wiki، یک‌بار ذخیره صفحه اولیه در رابط GitHub لازم است؛ پس از آن sync از workflow انجام می‌شود.

نسخه‌های منتشرشده را با تغییر صرف مستندات جایگزین نکنید. نتیجه تست‌های منطقی و تست‌های سخت‌افزاری را جداگانه ثبت کنید.

[بازگشت به فهرست](Home.md)

</div>
