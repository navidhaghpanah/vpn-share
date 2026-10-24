using System.Text.Json;
using System.Net;

namespace VpnShare;

public sealed class WidgetForm : GlassForm
{
    readonly SharingSession session=new();
    readonly OperationWorker lifecycle=new();
    string[] hostedCandidates=Array.Empty<string>();
    string driverStatus="Checking the packet driver…";
    bool driverAvailable;
    readonly GlassCombo source=new(),wired=new();
    readonly GlassField ssid=new(),password=new();
    readonly GlassButton wifiMode=new(){Text="Wi-Fi hotspot",Selected=true},lanMode=new(){Text="Ethernet"};
    readonly GlassButton toggle=new(){Text="Start sharing",Primary=true};
    readonly Label vpnState=new(),vpnDetails=new(),inputInfo=new(),status=new(),sourceCaption=new(),nameLabel=new(),passwordLabel=new();
    readonly Label clientCount=new(),upload=new(),download=new();
    readonly System.Windows.Forms.Timer timer=new(){Interval=1000};
    readonly NotifyIcon tray=new();
    readonly ToolTip tips=new(){AutoPopDelay=10000};
    readonly List<string> messages=new();
    readonly bool preview;
    readonly WidgetSettings settings;
    AdapterInfo[] physical=Array.Empty<AdapterInfo>();
    AdapterInfo[] adapters=Array.Empty<AdapterInfo>();
    ExternalVpnStatus? externalVpn;
    bool closeRequested,busy,refreshing,ethernet,quitting,ready,startFailed,recoveryFailed,securityBlocked,exitWithRecoveryPending;
    int ticks;
    CancellationTokenSource? operation;
    object? securityChecks;
    public bool InventoryReady=>ready;
    public WidgetForm(bool preview=false)
    {
        this.preview=preview;settings=WidgetSettings.Load();
        Text="VPN Share";ClientSize=new Size(440,720);MinimumSize=Size;MaximumSize=Size;MaximizeBox=false;
        var title=Label(this,"VPN Share",24,20,250,32,22,true);
        Label(this,"A PRIVATE CONNECTION. SHARED.",26,56,300,16,8,false,Glass.Muted);
        var pin=Button(this,"◇",342,22,30,30);pin.AccessibleName="Keep widget on top";
        pin.Click+=(_,_)=>{TopMost=!TopMost;pin.Selected=TopMost;pin.Text=TopMost?"◆":"◇";pin.Invalidate();};tips.SetToolTip(pin,"Keep on top");
        var close=Button(this,"×",380,22,30,30);close.AccessibleName="Close or minimize to tray";close.Click+=(_,_)=>Close();
        var vpn=new GlassCard{Location=new Point(24,86),Size=new Size(392,144)};Controls.Add(vpn);
        Style(vpnState,"●  LOOKING FOR VPN",18,14,355,20,9,true,Glass.Cyan);vpn.Controls.Add(vpnState);
        source.Location=new Point(17,47);source.Size=new Size(357,36);vpn.Controls.Add(source);source.AccessibleName="Connected VPN";
        Style(vpnDetails,"Your connected VPN will appear here.",18,99,350,22,10,false,Glass.Muted);vpn.Controls.Add(vpnDetails);
        var output=new GlassCard{Location=new Point(24,244),Size=new Size(392,207)};Controls.Add(output);
        Label(output,"Share through",17,13,330,25,12,true);
        wifiMode.SetBounds(16,47,175,37);lanMode.SetBounds(199,47,175,37);output.Controls.AddRange(new Control[]{wifiMode,lanMode});
        Style(nameLabel,"NETWORK NAME",18,97,170,18,8,true,Glass.Muted);Style(passwordLabel,"PASSWORD",202,97,170,18,8,true,Glass.Muted);output.Controls.AddRange(new Control[]{nameLabel,passwordLabel});
        ssid.SetBounds(16,119,175,43);password.SetBounds(199,119,175,43);password.Input.UseSystemPasswordChar=true;password.Input.MaxLength=63;ssid.Input.MaxLength=32;
        ssid.Input.AccessibleName="Wi-Fi network name";password.Input.AccessibleName="Wi-Fi password";ssid.Input.Text=settings.Ssid;password.Input.Text=settings.Password;
        output.Controls.AddRange(new Control[]{ssid,password});
        wired.SetBounds(17,123,357,35);wired.Visible=false;wired.AccessibleName="Ethernet output adapter";output.Controls.Add(wired);
        Style(inputInfo,"USB, Ethernet or Wi-Fi internet",18,173,350,20,9,false,Glass.Muted);output.Controls.Add(inputInfo);
        toggle.SetBounds(24,466,392,53);toggle.Font=new Font("Segoe UI",12,FontStyle.Bold);Controls.Add(toggle);
        Style(status,"Scanning your connections…",27,528,386,30,9,false,Glass.Muted);Controls.Add(status);status.AutoEllipsis=true;
        var stats=new GlassCard{Location=new Point(24,566),Size=new Size(392,75),Cursor=Cursors.Hand};Controls.Add(stats);
        Label(stats,"CLIENTS",18,12,105,17,8,true,Glass.Muted);Label(stats,"UPLOAD",146,12,105,17,8,true,Glass.Muted);Label(stats,"DOWNLOAD",270,12,110,17,8,true,Glass.Muted);
        Style(clientCount,"0",17,32,110,30,18,true,Glass.Ink);Style(upload,"0 B",145,32,115,30,18,true,Glass.Ink);Style(download,"0 B",269,32,113,30,18,true,Glass.Ink);stats.Controls.AddRange(new Control[]{clientCount,upload,download});
        stats.Click+=(_,_)=>ShowClients();clientCount.Click+=(_,_)=>ShowClients();
        var options=Button(this,"⚙  Options",24,657,120,34);options.AccessibleName="Options and diagnostics";options.Click+=(_,_)=>ShowOptions();
        var copy=Button(this,"Copy Wi-Fi",153,657,135,34);copy.Click+=(_,_)=>{if(!ethernet){Clipboard.SetText($"Network: {ssid.Input.Text}\nPassword: {password.Input.Text}");SetStatus("Wi-Fi details copied to clipboard.",false);}};
        var minimize=Button(this,"Hide",297,657,119,34);minimize.Click+=(_,_)=>HideToTray();
        Label(this,"VPN SHARE / "+Branding.Version,26,698,145,14,7,false,Color.FromArgb(101,129,156));
        var about=new LinkLabel{Text="About",Location=new Point(176,696),Size=new Size(50,18),Font=new Font("Segoe UI",8),BackColor=Color.Transparent,LinkColor=Glass.Muted,ActiveLinkColor=Glass.Ink,VisitedLinkColor=Glass.Muted,TextAlign=ContentAlignment.MiddleCenter};about.LinkClicked+=(_,_)=>ShowAbout();Controls.Add(about);
        var sponsor=new LinkLabel{Text="sirgsm.ir",Location=new Point(236,696),Size=new Size(120,18),Font=new Font("Segoe UI",8,FontStyle.Bold),BackColor=Color.Transparent,LinkColor=Glass.Cyan,ActiveLinkColor=Glass.Ink,VisitedLinkColor=Glass.Cyan,TextAlign=ContentAlignment.MiddleRight,AccessibleName="Visit SirGSM website"};
        sponsor.LinkClicked+=(_,_)=>{try{System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://sirgsm.ir"){UseShellExecute=true});}catch(Exception e){SetStatus("Could not open website: "+e.Message,true);}};
        Controls.Add(sponsor);
        var signature=Label(this,"NH",382,696,30,18,8,true,Glass.Muted);signature.TextAlign=ContentAlignment.MiddleRight;
        wifiMode.Click+=(_,_)=>SetOutput(false);lanMode.Click+=(_,_)=>SetOutput(true);
        source.SelectedIndexChanged+=(_,_)=>UpdateSelectedVpn();toggle.Click+=async(_,_)=>await ToggleAsync();
        session.Message+=AddLog;timer.Tick+=async(_,_)=>await TickAsync();
        Icon=WidgetIcon.Create();tray.Icon=Icon;tray.Text="VPN Share";tray.DoubleClick+=(_,_)=>RestoreWidget();
        var menu=new ContextMenuStrip();menu.Items.Add("Open widget",null,(_,_)=>RestoreWidget());menu.Items.Add("Stop sharing",null,async(_,_)=>await StopAsync());menu.Items.Add("Quit",null,(_,_)=>{quitting=true;Close();});tray.ContextMenuStrip=menu;
        Shown+=async(_,_)=>{await RefreshAsync(true);if(!preview){try{securityChecks=await Task.Run(SecuritySelfTest.Run);AddLog("Protected storage and installer-lock self-test passed.");}catch(Exception e){securityBlocked=true;AddLog(e.Message);SetStatus("Security preflight failed. Open Options for details.",true);}await RecoverAsync();SetControls();timer.Start();}};
        FormClosing+=OnClosing;AddLog(driverStatus);
    }
    static void Style(Label label,string text,int x,int y,int w,int h,float size,bool bold,Color color)
    {label.Text=text;label.SetBounds(x,y,w,h);label.Font=new Font("Segoe UI",size,bold?FontStyle.Bold:FontStyle.Regular);label.ForeColor=color;label.BackColor=Color.Transparent;label.TextAlign=ContentAlignment.MiddleLeft;label.AutoEllipsis=true;}
    static Label Label(Control parent,string text,int x,int y,int w,int h,float size,bool bold=false,Color? color=null)
    {var label=new Label();Style(label,text,x,y,w,h,size,bold,color??Glass.Ink);parent.Controls.Add(label);return label;}
    static GlassButton Button(Control parent,string text,int x,int y,int w,int h)
    {var button=new GlassButton{Text=text};button.SetBounds(x,y,w,h);parent.Controls.Add(button);return button;}
    void SetOutput(bool lan)
    {
        if(busy||session.Running)return;
        ethernet=lan;wifiMode.Selected=!lan;lanMode.Selected=lan;wifiMode.Invalidate();lanMode.Invalidate();
        ssid.Visible=password.Visible=passwordLabel.Visible=!lan;wired.Visible=lan;nameLabel.Text=lan?"OUTPUT ADAPTER":"NETWORK NAME";
        if(lan)wired.BringToFront();
    }
    async Task RefreshAsync(bool scanPhysical=false)
    {
        if(refreshing||busy||session.Running)return;refreshing=true;
        try {
            var result=await Task.Run(()=>{var a=AdapterCatalog.Read();return(a,scanPhysical?AdapterCatalog.ReadPhysicalDevices():physical,
                a.Any(x=>x.IsVpn&&x.Connected&&x.IPv4.Any(p=>!p.StartsWith("169.254.")))?null:ExternalVpnStatus.ReadExpressVpn(),
                scanPhysical?HostedHotspot.CapableAdapters():hostedCandidates,DriverFiles.Available,DriverFiles.Check());});
            if(IsDisposed||busy||session.Running)return;adapters=result.a;physical=result.Item2;externalVpn=result.Item3;hostedCandidates=result.Item4;driverAvailable=result.Item5;driverStatus=result.Item6;
            string? selected=(source.SelectedItem as VpnChoice)?.Adapter.Id;
            source.Items.Clear();
            foreach(var a in adapters.Where(x=>x.IsVpn&&x.Connected&&x.IPv4.Any(p=>!p.StartsWith("169.254."))))source.Items.Add(new VpnChoice(a));
            var choices=source.Items.Cast<VpnChoice>().ToArray();
            int index=Array.FindIndex(choices,x=>x.Adapter.Id==selected);
            if(index<0)index=Array.FindIndex(choices,x=>Routes.UsesInterface(IPAddress.Parse("1.1.1.1"),x.Adapter.Index));
            source.SelectedIndex=choices.Length>0?Math.Max(0,index):-1;
            string? selectedLan=(wired.SelectedItem as LanChoice)?.Adapter.Id;wired.Items.Clear();
            foreach(var a in adapters.Concat(physical).DistinctBy(x=>x.Id.Trim('{','}').ToLowerInvariant()).Where(x=>!x.IsVpn&&x.Kind=="Ethernet / virtual"&&!x.Description.Contains("Virtual",StringComparison.OrdinalIgnoreCase)&&x.Gateways.Length==0))wired.Items.Add(new LanChoice(a));
            if(wired.Items.Count>0)wired.SelectedIndex=Math.Max(0,Array.FindIndex(wired.Items.Cast<LanChoice>().ToArray(),x=>x.Adapter.Id==selectedLan));
            var input=adapters.FirstOrDefault(x=>x.Connected&&!x.IsVpn&&x.Kind=="USB tethering")??adapters.FirstOrDefault(x=>x.Connected&&!x.IsVpn&&x.Gateways.Length>0);
            inputInfo.Text=input==null?"Internet input detected by Windows":"Internet via "+(input.Kind=="USB tethering"?"USB mobile tethering":input.Name);
            UpdateSelectedVpn();
            if(source.Items.Count==0)SetStatus(externalVpn==null?"Connect a VPN to begin. We will detect it automatically.":"ExpressVPN needs a tunnel: use Lightway without Turbo or OpenVPN.",externalVpn!=null);
            else if(!driverAvailable)SetStatus("Network engine needs setup · open Options for details.",true);
            else if(!startFailed)SetStatus("Ready. Your devices will connect without an app.",false);
            ready=true;SetControls();
        }catch(Exception e){ready=true;AddLog(e.Message);SetStatus("Device scan failed. Open Options to retry.",true);}
        finally{refreshing=false;}
    }
    void UpdateSelectedVpn()
    {
        var selected=source.SelectedItem as VpnChoice;
        vpnState.Text=selected==null?"○  WAITING FOR VPN":"●  VPN DETECTED";vpnState.ForeColor=selected==null?Glass.Muted:Glass.Cyan;
        vpnDetails.Text=selected==null?"Connect IKEv2, WireGuard or your VPN client.":$"{selected.Adapter.IPv4.FirstOrDefault()}  ·  {selected.Adapter.Name}";
        if(selected==null&&externalVpn!=null){
            vpnState.Text="●  EXPRESSVPN · NO SHAREABLE ADAPTER";vpnState.ForeColor=Color.FromArgb(255,203,143);
            vpnDetails.Text=externalVpn.Protocol+" · tunnel adapter unavailable";
            tips.SetToolTip(vpnDetails,"ExpressVPN is connected, but this mode exposes no usable IPv4 tunnel. VPN Share cannot safely share the physical internet interface as a VPN.");
        }else tips.SetToolTip(vpnDetails,"");
    }
    async Task RecoverAsync()
    {
        if(!File.Exists(NetworkSetup.StatePath))return;busy=true;SetControls();
        try{SetStatus("Restoring the previous network session…",false);await lifecycle.TryRunAsync(()=>{SharingSession.Recover();return Task.CompletedTask;});SetStatus("Previous session restored. Ready to share.",false);}
        catch(Exception e){recoveryFailed=true;AddLog(e.Message);SetStatus("Previous session needs recovery. Select Restore network.",true);}
        finally{busy=false;SetControls();CompletePendingClose();}
    }
    async Task ToggleAsync()
    {
        if(securityBlocked){SetStatus("Security preflight failed. Restart after fixing the reported cause.",true);return;}
        if(busy)return;if(session.Running||session.NeedsRecovery||recoveryFailed){await StopAsync();return;}
        if(source.SelectedItem is not VpnChoice vpn){SetStatus("Connect a VPN first.",true);return;}
        AdapterInfo? destination=null;
        if(ethernet){destination=(wired.SelectedItem as LanChoice)?.Adapter;if(destination==null){SetStatus("Connect an Ethernet output adapter, then refresh.",true);return;}}
        busy=true;startFailed=false;operation=new();SetControls();SetStatus("Preparing your private connection…",false);
        try{
            settings.Ssid=ssid.Input.Text;settings.Password=password.Input.Text;settings.Save();
            var selectedVpn=vpn.Adapter;var output=destination;var network=ssid.Input.Text;var secret=password.Input.Text;
            var resolver=settings.Dns;var wifi=settings.WifiOutput;var token=operation.Token;
            await lifecycle.TryRunAsync(()=>session.StartAsync(selectedVpn,output,network,secret,resolver,token,wifi));
            SetStatus("Sharing is active. Connect your devices to get started.",false);
        }catch(OperationCanceledException){SetStatus("Sharing canceled. Network restored.",false);}
        catch(Exception e){startFailed=true;AddLog(e.ToString());SetStatus(driverAvailable?"Could not start sharing · details in Options.":"Network engine is unavailable · see Options.",true);}
        finally{busy=false;operation.Dispose();operation=null;SetControls();CompletePendingClose();}
    }
    async Task StopAsync()
    {
        if(busy)return;busy=true;SetControls();
        try{await lifecycle.TryRunAsync(()=>{session.Stop();SharingSession.Recover();return Task.CompletedTask;});recoveryFailed=false;SetStatus("Sharing stopped. Your network settings are restored.",false);}
        catch(Exception e){recoveryFailed=true;AddLog(e.ToString());SetStatus("Restoration needs attention · open Options.",true);}
        finally{busy=false;SetControls();CompletePendingClose();}
    }
    void SetControls()
    {
        bool editable=!busy&&!session.Running&&!session.NeedsRecovery&&!recoveryFailed&&!securityBlocked;source.Enabled=wired.Enabled=ssid.Enabled=password.Enabled=wifiMode.Enabled=lanMode.Enabled=editable;
        toggle.Enabled=!busy&&!securityBlocked&&(session.Running||session.NeedsRecovery||recoveryFailed||source.SelectedItem is VpnChoice);toggle.Text=securityBlocked?"Security check failed":busy?"Please wait…":(session.NeedsRecovery||recoveryFailed)?"Restore network":session.Running?"Stop sharing":"Start sharing";
        toggle.Primary=!session.Running;toggle.Invalidate();
    }
    async Task TickAsync()
    {
        if(session.Running){
            clientCount.Text=session.Clients.Length.ToString();upload.Text=Bytes(session.Uploaded);download.Text=Bytes(session.Downloaded);
            vpnState.Text=session.Connected?"●  SHARING VIA VPN":"●  WAITING FOR VPN";vpnState.ForeColor=session.Connected?Glass.Cyan:Color.FromArgb(255,203,143);
            if(!session.Connected)SetStatus("VPN interrupted. Client internet is paused.",true);
            else if(status.Text.StartsWith("VPN interrupted"))SetStatus("VPN restored. Sharing resumed automatically.",false);
        }else if((session.NeedsRecovery||recoveryFailed)&&!busy)SetStatus("Setup failed. Select Restore network before retrying.",true);
        else if(++ticks%5==0)await RefreshAsync();
        SaveRuntimeStatus();
    }
    internal static string Bytes(long value)=>value>=1073741824?$"{value/1073741824d:0.0} GB":value>=1048576?$"{value/1048576d:0.0} MB":value>=1024?$"{value/1024d:0.0} KB":$"{value} B";
    void SetStatus(string text,bool warning){status.Text=text;status.ForeColor=warning?Color.FromArgb(255,207,156):Glass.Muted;tips.SetToolTip(status,text);SaveRuntimeStatus();}
    void SaveRuntimeStatus()
    {
        if(preview)return;
        try{
            string directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"VPNShare");Directory.CreateDirectory(directory);
            string path=Path.Combine(directory,"runtime-status.json"),temporary=path+".tmp";
            File.WriteAllText(temporary,JsonSerializer.Serialize(new{Version="0.5.0-preview.11",Time=DateTimeOffset.UtcNow,Running=session.Running,Connected=session.Connected,Busy=busy,Status=status.Text,NetworkName=ssid.Input.Text,Gateway=session.Gateway,Clients=session.Clients,Uploaded=session.Uploaded,Downloaded=session.Downloaded,Dropped=session.Dropped,SecurityChecks=securityChecks,Log=messages}));
            File.Move(temporary,path,true);
        }catch{}
    }
    void AddLog(string text)
    {
        if(IsDisposed)return;if(InvokeRequired){try{BeginInvoke(()=>AddLog(text));}catch(InvalidOperationException){}return;}
        messages.Add($"[{DateTime.Now:HH:mm:ss}] {text}");if(messages.Count>150)messages.RemoveAt(0);
        SaveRuntimeStatus();
    }
    public void RenderOptions(string path)=>ShowOptions(path);
    public void RenderAbout(string path)=>ShowAbout(path);
    void ShowAbout(string? renderPath=null)
    {
        using var dialog=new GlassForm{Text="About VPN Share",ClientSize=new Size(440,440),StartPosition=FormStartPosition.CenterParent};
        Label(dialog,"VPN Share",24,22,350,40,23,true);
        Label(dialog,Branding.Version+" · Preview",26,70,380,24,11,false,Glass.Cyan);
        Label(dialog,Branding.Author,26,114,380,30,14,true);
        Label(dialog,"Phone: "+Branding.Phone,26,157,380,28,11);
        LinkLabel Link(string text,string url,int y){var link=new LinkLabel{Text=text,Location=new Point(26,y),Size=new Size(380,30),Font=new Font("Segoe UI",11),BackColor=Color.Transparent,LinkColor=Glass.Cyan,ActiveLinkColor=Glass.Ink,VisitedLinkColor=Glass.Cyan};link.LinkClicked+=(_,_)=>{try{System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url){UseShellExecute=true});}catch(Exception e){MessageBox.Show(dialog,e.Message,"Could not open link");}};dialog.Controls.Add(link);return link;}
        Link("Telegram: @"+Branding.Telegram,"https://t.me/"+Branding.Telegram,199);
        Link("sirgsm.ir",Branding.Website,242);
        var note=Label(dialog,"Personal-use preview. VPN disconnect, leak and crash-recovery acceptance tests are still pending.",26,294,380,65,10,false,Glass.Muted);note.AutoEllipsis=false;
        Button(dialog,"Close",24,383,392,40).Click+=(_,_)=>dialog.Close();
        if(renderPath!=null){dialog.StartPosition=FormStartPosition.Manual;dialog.Location=new Point(-30000,-30000);dialog.ShowInTaskbar=false;dialog.Shown+=(_,_)=>dialog.BeginInvoke(()=>{using var bitmap=new Bitmap(dialog.Width,dialog.Height);dialog.DrawToBitmap(bitmap,new Rectangle(0,0,bitmap.Width,bitmap.Height));bitmap.Save(renderPath,System.Drawing.Imaging.ImageFormat.Png);dialog.Close();});}
        dialog.ShowDialog(this);
    }
    void ShowOptions(string? renderPath=null)
    {
        using var dialog=new GlassForm{Text="VPN Share options",ClientSize=new Size(440,690),StartPosition=FormStartPosition.CenterParent};
        Label(dialog,"Options",24,20,320,40,22,true);Button(dialog,"×",378,24,32,32).Click+=(_,_)=>dialog.Close();
        Label(dialog,"WI-FI OUTPUT ADAPTER",26,78,370,18,8,true,Glass.Muted);
        var wifiOutput=new GlassCombo{Location=new Point(24,106),Size=new Size(392,36),AccessibleName="Wi-Fi output adapter",Enabled=!busy&&!session.Running};dialog.Controls.Add(wifiOutput);
        var wifiOptions=new List<(string Id,string Name)>{("auto","Automatic · prefer a spare AP card"),("","Windows Wi-Fi Direct · automatic radio")};
        var capable=hostedCandidates;
        wifiOptions.AddRange(adapters.Where(a=>a.Kind=="Wi-Fi"&&capable.Any(id=>Guid.Parse(id)==Guid.Parse(a.Id))).Select(a=>(a.Id,a.Name+" · dedicated Hosted AP")));
        foreach(var option in wifiOptions)wifiOutput.Items.Add(option.Name);
        wifiOutput.SelectedIndex=Math.Max(0,wifiOptions.FindIndex(x=>x.Id==settings.WifiOutput));
        Label(dialog,"DNS RESOLVER",26,169,370,18,8,true,Glass.Muted);var field=new GlassField{Location=new Point(24,193),Size=new Size(392,44)};field.Input.Text=settings.Dns;field.Input.PlaceholderText="Automatic VPN DNS";field.Enabled=!busy&&!session.Running;dialog.Controls.Add(field);
        var reveal=new CheckBox{Text="Show Wi-Fi password in widget",AutoSize=true,ForeColor=Glass.Ink,BackColor=Color.Transparent,Location=new Point(27,253),Checked=!password.Input.UseSystemPasswordChar};dialog.Controls.Add(reveal);reveal.CheckedChanged+=(_,_)=>password.Input.UseSystemPasswordChar=!reveal.Checked;
        Label(dialog,"ENGINE STATUS",26,291,370,18,8,true,Glass.Muted);
        var engine=Label(dialog,"",26,313,384,89,9,false,Glass.Muted);engine.AutoEllipsis=false;
        engine.Text=driverStatus;
        Label(dialog,"ACTIVITY",26,413,370,18,8,true,Glass.Muted);
        var activity=new TextBox{Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,BorderStyle=BorderStyle.None,BackColor=Color.FromArgb(22,36,55),ForeColor=Glass.Muted,Font=new Font("Consolas",8),Location=new Point(25,441),Size=new Size(390,130),Text=string.Join(Environment.NewLine,messages)};dialog.Controls.Add(activity);activity.SelectionStart=activity.TextLength;activity.ScrollToCaret();
        var scan=Button(dialog,"Refresh devices",24,584,188,40);scan.Click+=async(_,_)=>{dialog.Close();await RefreshAsync(true);};
        var export=Button(dialog,"Export diagnostics",224,584,192,40);export.Click+=(_,_)=>ExportDiagnostics(dialog);
        var save=Button(dialog,"Save options",24,636,392,40);save.Primary=true;save.Click+=(_,_)=>{if(!busy&&!session.Running){settings.Dns=field.Input.Text.Trim();settings.WifiOutput=wifiOptions[wifiOutput.SelectedIndex].Id;settings.Ssid=ssid.Input.Text;settings.Password=password.Input.Text;}settings.Save();dialog.Close();};
        if(renderPath!=null){
            dialog.StartPosition=FormStartPosition.Manual;dialog.Location=new Point(-30000,-30000);dialog.ShowInTaskbar=false;
            dialog.Shown+=(_,_)=>dialog.BeginInvoke(()=>{using var bitmap=new Bitmap(dialog.Width,dialog.Height);dialog.DrawToBitmap(bitmap,new Rectangle(0,0,bitmap.Width,bitmap.Height));bitmap.Save(renderPath,System.Drawing.Imaging.ImageFormat.Png);dialog.Close();});
        }
        dialog.ShowDialog(this);
    }
    void ShowClients()
    {
        using var dialog=new GlassForm{Text="Connected devices",ClientSize=new Size(440,400),StartPosition=FormStartPosition.CenterParent};Label(dialog,"Your devices",24,20,320,40,22,true);Button(dialog,"×",378,24,32,32).Click+=(_,_)=>dialog.Close();
        var leases=session.Clients;int y=85;
        if(leases.Length==0)Label(dialog,"No DHCP leases yet.\nConnect a device after sharing starts.",26,y,380,90,12,false,Glass.Muted);
        foreach(var lease in leases.Take(5)){var card=new GlassCard{Location=new Point(24,y),Size=new Size(392,48),Radius=16};dialog.Controls.Add(card);Label(card,(lease.Hostname==""?"Device":lease.Hostname)+"   ·   "+lease.Address,15,8,360,32,11);y+=57;}
        dialog.ShowDialog(this);
    }
    void ExportDiagnostics(IWin32Window owner)
    {
        using var save=new SaveFileDialog{FileName="VPNShare-diagnostics.json",Filter="JSON file|*.json"};if(save.ShowDialog(owner)!=DialogResult.OK)return;
        File.WriteAllText(save.FileName,JsonSerializer.Serialize(new{Version="0.5.0-preview.11",OS=Environment.OSVersion.ToString(),Adapters=adapters,Driver=DriverFiles.Check(),Log=messages,Notes="Wi-Fi password excluded. Includes local adapter names and IP addresses."},new JsonSerializerOptions{WriteIndented=true}));
    }
    void HideToTray(){if(preview)return;tray.Visible=true;Hide();}
    void RestoreWidget(){Show();WindowState=FormWindowState.Normal;Activate();tray.Visible=false;}
    void CompletePendingClose()
    {
        if(closeRequested&&!IsDisposed){closeRequested=false;quitting=true;BeginInvoke(()=>Close());}
    }
    async void OnClosing(object? sender,FormClosingEventArgs e)
    {
        if(preview)return;
        if(busy){e.Cancel=true;closeRequested=true;operation?.Cancel();SetStatus("Finishing network cleanup before closing…",false);return;}
        if(session.Running&&!quitting){e.Cancel=true;HideToTray();return;}
        if(!exitWithRecoveryPending&&(session.Running||File.Exists(NetworkSetup.StatePath))){
            e.Cancel=true;await StopAsync();
            if(File.Exists(NetworkSetup.StatePath)){
                AddLog("Recovery remains pending. Protection rules and the journal are retained for the next launch.");
                MessageBox.Show(this,"Network recovery needs attention. The saved journal and protection rules are retained; the recovery helper and next launch will retry. See Options activity for the cause.","Recovery pending",MessageBoxButtons.OK,MessageBoxIcon.Warning);
                exitWithRecoveryPending=true;
            }
            quitting=true;Close();return;
        }
        timer.Stop();tray.Visible=false;
    }
    protected override void Dispose(bool disposing){if(disposing){timer.Dispose();tray.Dispose();tips.Dispose();}base.Dispose(disposing);}
    record VpnChoice(AdapterInfo Adapter){public override string ToString()=>Adapter.Name.Replace("OpenVPN WinTUN Adapter","",StringComparison.OrdinalIgnoreCase).Trim();}
    record LanChoice(AdapterInfo Adapter){public override string ToString()=>Adapter.Name+(Adapter.Connected?"":" · disconnected");}
}

internal static class WidgetIcon
{
    public static Icon Create()
    {
        using var stream=typeof(WidgetIcon).Assembly.GetManifestResourceStream("VpnShare.AppIcon")
            ??throw new InvalidOperationException("SirGSM app icon is missing.");
        using var icon=new Icon(stream);
        return (Icon)icon.Clone();
    }
}
