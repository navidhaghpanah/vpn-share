using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace VpnShare;

public sealed class HostedSettingsBackup
{
    public byte[] Connection {get;set;}=Array.Empty<byte>();
    public byte[] Enabled {get;set;}=Array.Empty<byte>();
    public byte[] KeyProtected {get;set;}=Array.Empty<byte>();
    public bool Passphrase {get;set;}
    public bool Persistent {get;set;}
    public string OwnedAdapterId {get;set;}="";
    public byte[] ExpectedConnection {get;set;}=Array.Empty<byte>();
    public bool StartRequested {get;set;}
}

// Hosted Network is used only to create the AP. DHCP, DNS, NAT and leak guards
// remain owned by VPN Share; this does not enable Internet Connection Sharing.
public sealed class HostedHotspot : IDisposable
{
    const uint Dot11PowerStateInvalid=0x80342002;
    const int ApStartFailed=19;
    const int StartAttempts=16;
    IntPtr handle;
    bool started;
    public HostedHotspot(){Check(WlanOpenHandle(2,IntPtr.Zero,out _,out handle),"open WLAN");}
    public void Initialize()
    {
        Check(WlanHostedNetworkInitSettings(handle,out var reason,IntPtr.Zero),"initialize AP settings");
        if(reason!=0)throw new InvalidOperationException("Wi-Fi AP initialization failed: "+reason);
    }
    static void Check(uint error,string action){if(error!=0)throw new Win32Exception((int)error,"Wi-Fi AP: "+action);}
    byte[] Property(int opcode)
    {
        Check(WlanHostedNetworkQueryProperty(handle,opcode,out var size,out var data,out _,IntPtr.Zero),"read AP settings");
        try{if(size>4096)throw new InvalidDataException("Invalid AP property size.");var bytes=new byte[size];Marshal.Copy(data,bytes,0,(int)size);return bytes;}finally{WlanFreeMemory(data);}
    }
    void Set(int opcode,byte[] bytes){Check(WlanHostedNetworkSetProperty(handle,opcode,(uint)bytes.Length,bytes,out var reason,IntPtr.Zero),"set AP property ("+opcode+")");if(reason!=0)throw new InvalidOperationException("Wi-Fi AP rejected settings: "+reason);}
    (int State,Guid Id) Status()
    {
        Check(WlanHostedNetworkQueryStatus(handle,out var data,IntPtr.Zero),"read AP status");
        try{int state=Marshal.ReadInt32(data);return(state,state==0?Guid.Empty:Marshal.PtrToStructure<Guid>(IntPtr.Add(data,4)));}finally{WlanFreeMemory(data);}
    }
    public bool Capable(string adapterId)
    {
        var id=Guid.Parse(adapterId);uint error=WlanQueryInterface(handle,ref id,15,IntPtr.Zero,out uint size,out var data,out _);
        if(error!=0)return false;
        try{return size==4&&Marshal.ReadInt32(data)!=0;}finally{WlanFreeMemory(data);}
    }
    public static string[] CapableAdapters()
    {
        try{using var ap=new HostedHotspot();return AdapterCatalog.Read().Where(a=>a.Kind=="Wi-Fi"&&ap.Capable(a.Id)).Select(a=>a.Id).ToArray();}catch{return Array.Empty<string>();}
    }
    public static byte[] ConnectionSettings(string ssid)
    {
        var name=Encoding.UTF8.GetBytes(ssid);if(name.Length is <1 or >32)throw new ArgumentException("Wi-Fi name must contain 1 to 32 UTF-8 bytes.");
        var result=new byte[40];BitConverter.GetBytes((uint)name.Length).CopyTo(result,0);name.CopyTo(result,4);BitConverter.GetBytes(32u).CopyTo(result,36);return result;
    }
    public event Action<string>? Message;
    public static bool ShouldRetryStart(uint error,int reason,int state,int attempt)=>error==Dot11PowerStateInvalid&&reason==ApStartFailed&&state==1&&attempt<StartAttempts-1;
    public static bool CanUseAsOutput(AdapterInfo adapter)=>adapter.Kind=="Wi-Fi"&&!adapter.IsVpn&&!adapter.Connected;
    public static bool CanResetOutput(AdapterInfo adapter)=>CanUseAsOutput(adapter);
    async Task EnsureAvailable(string selected,CancellationToken token)
    {
        if(Status().State!=0)return;
        var adapter=AdapterCatalog.Read().SingleOrDefault(a=>Guid.Parse(a.Id)==Guid.Parse(selected));
        if(adapter==null||!CanResetOutput(adapter))throw new InvalidOperationException("Hosted AP is unavailable. Automatic reset refused because the output is connected.");
        Message?.Invoke("Hosted AP unavailable; recovering the idle output adapter once…");
        var id=Guid.Parse(selected).ToString();
        await Task.Run(()=>NetworkSetup.Run($"$a=@(Get-NetAdapter -Physical | Where-Object {{[guid]$_.InterfaceGuid -eq [guid]'{id}'}}); if($a.Count -ne 1 -or $a[0].Status -ne 'Disconnected'){{throw 'Output is not idle; reset refused'}}; $a[0] | Restart-NetAdapter -Confirm:$false -ErrorAction Stop"),token);
        // No AP properties have been changed yet. Re-open the WLAN client after rebind.
        WlanCloseHandle(handle,IntPtr.Zero);handle=IntPtr.Zero;
        Check(WlanOpenHandle(2,IntPtr.Zero,out _,out handle),"reopen WLAN after output recovery");
        for(int attempt=0;attempt<60;attempt++){
            token.ThrowIfCancellationRequested();Initialize();
            if(Status().State!=0){Message?.Invoke("Hosted AP became available after output recovery.");return;}
            await Task.Delay(250,token);
        }
        throw new InvalidOperationException("Hosted AP remains unavailable after one idle-output reset. Windows did not recreate the virtual AP; no internet/VPN adapter was reset.");
    }
    public async Task<AdapterInfo> StartAsync(string selected,string ssid,string password,SessionState session,CancellationToken token)
    {
        var settings=ConnectionSettings(ssid);
        if(password.Length is <8 or >63||password.Any(c=>c<32||c>126))throw new ArgumentException("Use 8 to 63 printable English characters for the Wi-Fi password.");
        var capable=AdapterCatalog.Read().Where(a=>a.Kind=="Wi-Fi"&&Capable(a.Id)).ToArray();
        if(capable.Length!=1||!Guid.Parse(capable[0].Id).Equals(Guid.Parse(selected)))throw new InvalidOperationException("Windows cannot select this AP adapter unambiguously. Choose the only Hosted AP capable card, or use automatic Wi-Fi Direct.");
        if(!CanUseAsOutput(capable[0]))throw new InvalidOperationException("The selected Wi-Fi card became connected. Choose an unused output card.");
        Initialize();
        await EnsureAvailable(selected,token);
        var initialStatus=Status();
        if(initialStatus.State==2)throw new InvalidOperationException("Another Hosted Network is already running. Its settings were not changed.");
        var backup=new HostedSettingsBackup{Connection=Property(0),Enabled=Property(3),OwnedAdapterId=initialStatus.Id==Guid.Empty?"":initialStatus.Id.ToString(),ExpectedConnection=settings};
        if(backup.Connection.Length!=40||backup.Enabled.Length!=4)throw new InvalidDataException("Unexpected Windows AP settings layout. Nothing was changed.");
        Check(WlanHostedNetworkQuerySecondaryKey(handle,out var length,out var key,out var pass,out var persistent,out _,IntPtr.Zero),"read previous AP key");
        try{
            if(length>64)throw new InvalidDataException("Invalid previous AP key size.");
            var bytes=new byte[length];if(length>0)Marshal.Copy(key,bytes,0,(int)length);
            backup.KeyProtected=ProtectedData.Protect(bytes,null,DataProtectionScope.LocalMachine);CryptographicOperations.ZeroMemory(bytes);
            backup.Passphrase=pass;backup.Persistent=persistent;
        }finally{if(key!=IntPtr.Zero)WlanFreeMemory(key);}
        session.HostedSettings=backup;NetworkSetup.Save(session);
        Set(3,BitConverter.GetBytes(1));Set(0,settings);
        var secret=Encoding.ASCII.GetBytes(password+"\0");
        try{Check(WlanHostedNetworkSetSecondaryKey(handle,(uint)secret.Length,secret,true,false,out var reason,IntPtr.Zero),"set temporary AP password");if(reason!=0)throw new InvalidOperationException("AP key rejected: "+reason);}finally{CryptographicOperations.ZeroMemory(secret);}
        backup.StartRequested=true;NetworkSetup.Save(session);
        uint startError=0;int startReason=0,startState=0;
        for(int attempt=0;attempt<StartAttempts;attempt++){
            token.ThrowIfCancellationRequested();
            startError=WlanHostedNetworkStartUsing(handle,out startReason,IntPtr.Zero);startState=Status().State;
            if(startError==0&&startReason==0){started=true;break;}
            if(!ShouldRetryStart(startError,startReason,startState,attempt))break;
            if(attempt==0)Message?.Invoke("The Wi-Fi output is waking from a low-power state; waiting for the driver before retrying AP start…");
            await Task.Delay(1000,token);
        }
        if(!started){
            if(startError==Dot11PowerStateInvalid)throw new InvalidOperationException($"The Wi-Fi output stayed powered down for {StartAttempts-1} seconds. Windows rejected AP start after bounded retries (reason {startReason}; state {startState}; 0x{startError:X8}).");
            Check(startError,$"start AP (Windows reason {startReason}; state {startState})");
            throw new InvalidOperationException("AP could not start: "+startReason);
        }
        for(int attempt=0;attempt<80;attempt++){
            token.ThrowIfCancellationRequested();var status=Status();
            if(status.State==2&&status.Id!=Guid.Empty){
                if(backup.OwnedAdapterId!=status.Id.ToString()){backup.OwnedAdapterId=status.Id.ToString();NetworkSetup.Save(session);}
                var adapter=AdapterCatalog.Read().FirstOrDefault(a=>Guid.Parse(a.Id)==status.Id);if(adapter!=null)return adapter;
            }
            await Task.Delay(250,token);
        }
        throw new TimeoutException("The selected Wi-Fi card did not expose its AP interface within 20 seconds.");
    }
    public static void Restore(SessionState session)
    {
        var backup=session.HostedSettings;if(backup==null)return;
        using var ap=new HostedHotspot();
        for(int attempt=0;attempt<50&&ap.Status().State==2;attempt++)Thread.Sleep(100);
        var current=ap.Status();
        if(current.State==2){
            if(!CanStopOwned(session,current.Id,ap.Property(0),WidgetSettings.Load().Ssid))throw new InvalidOperationException("A different AP is active. Its adapter or SSID does not match the saved VPN Share session; recovery retained the journal.");
            Check(WlanHostedNetworkForceStop(ap.handle,out var reason,IntPtr.Zero),"stop the journaled AP retained by Windows");
            if(reason!=0)throw new InvalidOperationException("Windows could not stop the owned AP: "+reason);
            for(int attempt=0;attempt<50&&ap.Status().State==2;attempt++)Thread.Sleep(100);
            if(ap.Status().State==2)throw new InvalidOperationException("Windows still holds the owned AP after stop. Recovery retained the journal.");
        }
        if(backup.Connection.Length!=40||backup.Enabled.Length!=4)throw new InvalidDataException("Invalid saved AP configuration.");
        var key=ProtectedData.Unprotect(backup.KeyProtected,null,DataProtectionScope.LocalMachine);
        try{if(key.Length>64)throw new InvalidDataException("Invalid saved AP key.");Check(WlanHostedNetworkSetSecondaryKey(ap.handle,(uint)key.Length,key.Length==0?null:key,backup.Passphrase,backup.Persistent,out var reason,IntPtr.Zero),"restore AP key");if(reason!=0)throw new InvalidOperationException("AP key restoration failed: "+reason);}finally{CryptographicOperations.ZeroMemory(key);}
        ap.Set(0,backup.Connection);ap.Set(3,backup.Enabled);session.HostedSettings=null;NetworkSetup.Save(session);
    }
    public static bool CanStopOwned(SessionState session,Guid currentId,byte[] currentSettings,string legacySsid)
    {
        var backup=session.HostedSettings;
        if(backup==null||(!backup.StartRequested&&!session.HotspotOwned)||currentSettings.Length!=40)return false;
        var recorded=string.IsNullOrEmpty(backup.OwnedAdapterId)?session.AdapterId:backup.OwnedAdapterId;
        if(!Guid.TryParse(recorded,out var owned)||owned==Guid.Empty||owned!=currentId)return false;
        byte[] expected;
        if(backup.ExpectedConnection.Length==40)expected=backup.ExpectedConnection;
        else if(backup.ExpectedConnection.Length==0&&session.HotspotOwned){try{expected=ConnectionSettings(legacySsid);}catch(ArgumentException){return false;}}
        else return false;
        uint length=BitConverter.ToUInt32(expected);
        return length is >0 and <=32&&BitConverter.ToUInt32(currentSettings)==length&&expected.AsSpan(4,(int)length).SequenceEqual(currentSettings.AsSpan(4,(int)length));
    }
    public void Dispose()
    {
        if(handle==IntPtr.Zero)return;
        try{if(started)Check(WlanHostedNetworkStopUsing(handle,out _,IntPtr.Zero),"stop owned AP");}
        finally{WlanCloseHandle(handle,IntPtr.Zero);handle=IntPtr.Zero;started=false;}
    }
    [DllImport("wlanapi.dll")]static extern uint WlanOpenHandle(uint version,IntPtr reserved,out uint negotiated,out IntPtr handle);
    [DllImport("wlanapi.dll")]static extern uint WlanCloseHandle(IntPtr handle,IntPtr reserved);
    [DllImport("wlanapi.dll")]static extern void WlanFreeMemory(IntPtr memory);
    [DllImport("wlanapi.dll")]static extern uint WlanQueryInterface(IntPtr handle,ref Guid id,int opcode,IntPtr reserved,out uint size,out IntPtr data,out int type);
    [DllImport("wlanapi.dll")]static extern uint WlanHostedNetworkQueryProperty(IntPtr handle,int opcode,out uint size,out IntPtr data,out int type,IntPtr reserved);
    [DllImport("wlanapi.dll")]static extern uint WlanHostedNetworkSetProperty(IntPtr handle,int opcode,uint size,byte[] data,out int reason,IntPtr reserved);
    [DllImport("wlanapi.dll")]static extern uint WlanHostedNetworkQueryStatus(IntPtr handle,out IntPtr status,IntPtr reserved);
    [DllImport("wlanapi.dll")]static extern uint WlanHostedNetworkQuerySecondaryKey(IntPtr handle,out uint size,out IntPtr data,[MarshalAs(UnmanagedType.Bool)]out bool passphrase,[MarshalAs(UnmanagedType.Bool)]out bool persistent,out int reason,IntPtr reserved);
    [DllImport("wlanapi.dll")]static extern uint WlanHostedNetworkSetSecondaryKey(IntPtr handle,uint size,byte[]? data,[MarshalAs(UnmanagedType.Bool)]bool passphrase,[MarshalAs(UnmanagedType.Bool)]bool persistent,out int reason,IntPtr reserved);
    [DllImport("wlanapi.dll")]static extern uint WlanHostedNetworkStartUsing(IntPtr handle,out int reason,IntPtr reserved);
    [DllImport("wlanapi.dll")]static extern uint WlanHostedNetworkInitSettings(IntPtr handle,out int reason,IntPtr reserved);
    [DllImport("wlanapi.dll")]static extern uint WlanHostedNetworkStopUsing(IntPtr handle,out int reason,IntPtr reserved);
    [DllImport("wlanapi.dll")]static extern uint WlanHostedNetworkForceStop(IntPtr handle,out int reason,IntPtr reserved);
}
