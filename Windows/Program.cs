using System.Text.Json;

[assembly:System.Runtime.InteropServices.DefaultDllImportSearchPaths(System.Runtime.InteropServices.DllImportSearchPath.System32)]

namespace VpnShare;

internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        if(args.Length==3&&args[0]=="--watchdog"&&int.TryParse(args[1],out var parent)&&long.TryParse(args[2],out var birth)){RecoveryWatchdog.Run(parent,birth);return;}
        if (args.Contains("--diagnostics"))
        {
            var path = args.SkipWhile(x => x != "--diagnostics").Skip(1).FirstOrDefault()
                ?? Path.Combine(AppContext.BaseDirectory, "diagnostics.json");
            File.WriteAllText(path, JsonSerializer.Serialize(new {
                Version = "0.5.0-preview.5", OS = Environment.OSVersion.ToString(),
                Adapters = AdapterCatalog.Read(), Driver = DriverFiles.Check(),
                PacketDriver = NdisDevice.Inspect(),
                HotspotPlatform = HotspotPlatform.Inspect(),
                Notes = "Read-only inventory. No packet capture, hotspot or network changes performed."
            }, new JsonSerializerOptions { WriteIndented = true }));
            return;
        }
        ApplicationConfiguration.Initialize();
        if(args.Length>=2&&args[0]=="--export-icon"){using var icon=WidgetIcon.Create();using var file=File.Create(args[1]);icon.Save(file);if(args.Length==3){using var bitmap=icon.ToBitmap();bitmap.Save(args[2],System.Drawing.Imaging.ImageFormat.Png);}return;}
        if(args.Contains("--render-preview")||args.Contains("--render-options")||args.Contains("--render-about")) {
            using var preview=new WidgetForm(true);
            preview.StartPosition=FormStartPosition.Manual;
            preview.Location=new Point(-30000,-30000);preview.ShowInTaskbar=false;
            preview.Show();
            var deadline=DateTime.UtcNow.AddSeconds(15);
            while(!preview.InventoryReady && DateTime.UtcNow<deadline){Application.DoEvents();Thread.Sleep(20);}
            preview.PerformLayout();
            if(args.Contains("--render-about")){preview.RenderAbout(args.SkipWhile(x=>x!="--render-about").Skip(1).First());return;}
            if(args.Contains("--render-options")){preview.RenderOptions(args.SkipWhile(x=>x!="--render-options").Skip(1).First());return;}
            using var bitmap=new System.Drawing.Bitmap(preview.Width,preview.Height);
            preview.DrawToBitmap(bitmap,new Rectangle(0,0,bitmap.Width,bitmap.Height));
            bitmap.Save(args.SkipWhile(x=>x!="--render-preview").Skip(1).First(),System.Drawing.Imaging.ImageFormat.Png);
            return;
        }
        using var single = new Mutex(true, "Global\\NavidVPNShare-Session", out var first);
        if (!first) { MessageBox.Show("An older VPN Share window is still running. Quit it from the tray before opening this version. If its recovery is stuck, end only VPNShare.exe in Task Manager, then open this new build to restore the saved session.","Another version is running"); return; }
        try {Application.Run(new WidgetForm());}
        catch(Exception e) {MessageBox.Show(e.Message,"VPN Share could not start",MessageBoxButtons.OK,MessageBoxIcon.Error);}
    }
}
