using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;

namespace VpnShare;

public sealed class SessionState
{
    public string AdapterId {get;set;}="";
    public string AdapterName {get;set;}="";
    public int DownstreamIndex {get;set;}
    public int VpnIndex {get;set;}
    public string VpnIp {get;set;}="";
    public string VpnId {get;set;}="";
    public string VpnName {get;set;}="";
    public string Gateway {get;set;}="";
    public string OriginalConfiguration {get;set;}="";
    public List<Guid> GuardKeys {get;set;}=new();
    public List<string> NdisInterfaces {get;set;}=new();
    public List<string> WifiRadios {get;set;}=new();
    public string FirewallRule {get;set;}="VPNShare-"+Guid.NewGuid().ToString("N");
    public bool NetworkTouched {get;set;}
    public bool HotspotOwned {get;set;}
    public HotspotBackup? PreviousHotspot{get;set;}
    public HostedSettingsBackup? HostedSettings{get;set;}
    public bool UseWindowsKernel{get;set;}
    public string NativeNatName{get;set;}="";
}

public static class NetworkSetup
{
    public static string StatePath=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"VPNShare","session.json");
    static void SecureDirectory()
    {
        ProtectedStorage.EnsureDirectory(Path.GetDirectoryName(StatePath)!);
    }
    public static void Save(SessionState state)
    {
        SecureDirectory();
        var temporary=StatePath+"."+Guid.NewGuid().ToString("N")+".tmp";
        using(var file=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None))JsonSerializer.Serialize(file,state);
        File.Move(temporary,StatePath,true);
    }
    public static SessionState? Load()
    {
        if(!File.Exists(StatePath))return null;
        SecureDirectory();
        ProtectedStorage.CheckFile(StatePath);
        return JsonSerializer.Deserialize<SessionState>(File.ReadAllText(StatePath))
            ??throw new InvalidOperationException("The recovery journal is invalid. No network changes were made.");
    }
    public static string Run(string script)
    {
        var start=new ProcessStartInfo(PowerShellPath) {UseShellExecute=false,CreateNoWindow=true,RedirectStandardError=true,RedirectStandardOutput=true};
        start.ArgumentList.Add("-NoProfile");start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-EncodedCommand");
        start.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';try {"+script+";exit 0}catch{[Console]::Error.WriteLine(($_ | Out-String));exit 1}")));
        using var process=Process.Start(start) ?? throw new InvalidOperationException("PowerShell could not start.");
        var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        if(!process.WaitForExit(45000)) {process.Kill(true);throw new TimeoutException("Windows network operation timed out.");}
        Task.WaitAll(stdout,stderr);
        if(process.ExitCode!=0) throw new InvalidOperationException(string.IsNullOrWhiteSpace(stderr.Result)?$"Windows network helper failed (exit {process.ExitCode}). Output: {stdout.Result.Trim()}":stderr.Result.Trim());
        return stdout.Result.Trim();
    }
    static string Quote(string value)=>"'"+value.Replace("'","''")+"'";
    public static string PowerShellPath=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","WindowsPowerShell","v1.0","powershell.exe");
    public static void CheckConflicts()
    {
        Run("if(Get-NetNat -ErrorAction SilentlyContinue){throw 'An existing Windows NAT is active. VPN Share will not modify that network.'}");
    }
    public static string ChooseGateway()
    {
        var occupied=Run("ConvertTo-Json -InputObject @((Get-NetRoute -AddressFamily IPv4).DestinationPrefix) -Compress");
        var prefixes=JsonSerializer.Deserialize<string[]>(occupied) ?? Array.Empty<string>();
        return SubnetSelector.Choose(prefixes);
    }
    public static string CaptureAdapterConfiguration(string adapterId)
    {
        return Run($"$a=Get-NetAdapter -IncludeHidden | Where-Object {{[guid]$_.InterfaceGuid -eq [guid]{Quote(Guid.Parse(adapterId).ToString("B"))}}}; if(@($a).Count -ne 1){{throw 'Destination adapter not found'}}; $i=$a.ifIndex; $p=Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue; if(-not $p){{if($a.Status -ne 'Disabled'){{throw 'IPv4 interface not found'}}; $p=[pscustomobject]@{{Dhcp='Enabled';Forwarding='Disabled';NlMtu=1500}}}}; [pscustomobject]@{{Disabled=($a.Status -eq 'Disabled'); Dhcp=[string]$p.Dhcp; Forwarding=[string]$p.Forwarding; Mtu=$p.NlMtu; Addresses=@(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {{[pscustomobject]@{{IPAddress=$_.IPAddress; PrefixLength=[int]$_.PrefixLength; PrefixOrigin=[string]$_.PrefixOrigin}}}})}} | ConvertTo-Json -Depth 5 -Compress");
    }
    public static void Snapshot(SessionState state)
    {
        state.OriginalConfiguration=CaptureAdapterConfiguration(state.AdapterId);
        Save(state);
    }
    public static void Configure(SessionState state)
    {
        state.NetworkTouched=true;Save(state);
        Run($"$a=Get-NetAdapter -IncludeHidden | Where-Object {{[guid]$_.InterfaceGuid -eq [guid]{Quote(state.AdapterId)}}}; if(@($a).Count -ne 1){{throw 'Destination adapter not found'}}; if($a.Status -eq 'Disabled'){{$a | Enable-NetAdapter -Confirm:$false}}; $i=$a.ifIndex; Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -PolicyStore ActiveStore -Dhcp Disabled; Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Remove-NetIPAddress -PolicyStore ActiveStore -Confirm:$false; New-NetIPAddress -InterfaceIndex $i -IPAddress {Quote(state.Gateway)} -PrefixLength 24 -AddressFamily IPv4 -PolicyStore ActiveStore | Out-Null; Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -PolicyStore ActiveStore -NlMtuBytes 1280 -Forwarding Disabled; New-NetFirewallRule -Name {Quote(state.FirewallRule)} -DisplayName 'VPN Share DHCP and DNS' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 67,53 -InterfaceAlias $a.Name -Profile Any -Program {Quote(Environment.ProcessPath!)} | Out-Null; New-NetFirewallRule -Name {Quote(state.FirewallRule+"-TCP")} -DisplayName 'VPN Share DNS TCP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 53 -InterfaceAlias $a.Name -Profile Any -Program {Quote(Environment.ProcessPath!)} | Out-Null");
    }
    public static void WaitForGateway(SessionState state)
    {
        Run($"$deadline=[DateTime]::UtcNow.AddSeconds(20); $last='Missing'; do {{$a=Get-NetAdapter -IncludeHidden | Where-Object {{[guid]$_.InterfaceGuid -eq [guid]{Quote(Guid.Parse(state.AdapterId).ToString())}}}; if(-not $a){{throw 'Hotspot adapter disappeared before addressing completed'}}; $ip=Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -IPAddress {Quote(IPAddress.Parse(state.Gateway).ToString())} -PolicyStore ActiveStore -ErrorAction SilentlyContinue; if($ip){{$last=[string]$ip.AddressState;if($last -eq 'Preferred'){{exit 0}};if($last -eq 'Duplicate'){{throw 'The hotspot gateway address conflicts with another device'}}}}; Start-Sleep -Milliseconds 200}} while([DateTime]::UtcNow -lt $deadline); throw ('Hotspot gateway is not ready. Address state: '+$last+'; adapter: '+$a.Status)");
    }
    public static void Restore(SessionState state,Action? stopHotspot=null)
    {
        NdisRecovery.Restore(state);
        if(state.UseWindowsKernel){if(state.NetworkTouched)SetForwarding(state,false);NativeNatEngine.Remove(state);}
        if(state.NetworkTouched) {
            var snapshot=JsonSerializer.Deserialize<JsonElement>(state.OriginalConfiguration);
            var commands=new StringBuilder();
            commands.Append($"$a=Get-NetAdapter -IncludeHidden | Where-Object {{[guid]$_.InterfaceGuid -eq [guid]{Quote(state.AdapterId)}}}; if($a -and $a.Status -ne 'Disabled'){{$i=$a.ifIndex; Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -PolicyStore ActiveStore -Forwarding Disabled; Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -IPAddress {Quote(state.Gateway)} -ErrorAction SilentlyContinue | Remove-NetIPAddress -PolicyStore ActiveStore -Confirm:$false; ");
            if(snapshot.GetProperty("Dhcp").GetString()=="Enabled") commands.Append("Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -PolicyStore ActiveStore -Dhcp Enabled; ");
            else foreach(var address in snapshot.GetProperty("Addresses").EnumerateArray()) {
                if(address.GetProperty("PrefixOrigin").GetString()=="Manual")
                    commands.Append($"if(-not(Get-NetIPAddress -InterfaceIndex $i -IPAddress {Quote(address.GetProperty("IPAddress").GetString()!)} -ErrorAction SilentlyContinue)){{New-NetIPAddress -InterfaceIndex $i -IPAddress {Quote(address.GetProperty("IPAddress").GetString()!)} -PrefixLength {address.GetProperty("PrefixLength").GetInt32()} -PolicyStore ActiveStore | Out-Null}}; ");
            }
            commands.Append($"Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -PolicyStore ActiveStore -NlMtuBytes {snapshot.GetProperty("Mtu").GetInt32()}; ");
            // Restore prior forwarding only after packet engine is stopped; guards remain until restoration completes.
            if(snapshot.GetProperty("Forwarding").GetString()=="Enabled")
                commands.Append("Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -PolicyStore ActiveStore -Forwarding Enabled; ");
            if(snapshot.TryGetProperty("Disabled",out var disabled) && disabled.GetBoolean()) commands.Append("$a | Disable-NetAdapter -Confirm:$false; ");
            commands.Append($"}}; Get-NetFirewallRule -Name {Quote(state.FirewallRule)},{Quote(state.FirewallRule+"-TCP")} -ErrorAction SilentlyContinue | Remove-NetFirewallRule");
            Run(commands.ToString());state.NetworkTouched=false;Save(state);
        }
        stopHotspot?.Invoke();
        HostedHotspot.Restore(state);
        Guard.Remove(state,()=>Save(state));
        VpnShare.WifiRadios.Restore(state).GetAwaiter().GetResult();
        HotspotPlatform.RestoreAsync(state).GetAwaiter().GetResult();
        File.Delete(StatePath);
    }
    public static void SetForwarding(SessionState state,bool enabled)
    {
        var id=Guid.Parse(state.AdapterId);
        Run($"$a=Get-NetAdapter -IncludeHidden | Where-Object {{[guid]$_.InterfaceGuid -eq [guid]'{id}'}};if($a -and $a.Status -ne 'Disabled'){{$p=Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue;if($p){{Set-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -PolicyStore ActiveStore -Forwarding {(enabled?"Enabled":"Disabled")}}}}}");
    }
}
