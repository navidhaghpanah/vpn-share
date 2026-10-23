using System.Text.Json;
using Windows.Networking.Connectivity;
using Windows.Networking.NetworkOperators;

namespace VpnShare;

public sealed class SharedAdapterBackup
{
    public string Id{get;set;}="";
    public int Role{get;set;}
    public bool Virtual{get;set;}
}
public sealed class HotspotBackup
{
    public bool Enabled{get;set;}
    public bool Touched{get;set;}
    public string ProfileAdapter{get;set;}="";
    public List<SharedAdapterBackup> Sharing{get;set;}=new();
}

public static class HotspotPlatform
{
    static ConnectionProfile? Profile(string adapter="")=>NetworkInformation.GetConnectionProfiles().FirstOrDefault(p=>p.NetworkAdapter?.NetworkAdapterId.ToString()==adapter)??NetworkInformation.GetInternetConnectionProfile();
    public static object Inspect()
    {
        try{var profile=Profile();if(profile==null)return new{State="No internet profile"};var manager=NetworkOperatorTetheringManager.CreateFromConnectionProfile(profile);return new{State=manager.TetheringOperationalState.ToString(),Profile=profile.ProfileName};}
        catch(Exception e){return new{State="Unavailable",Error=e.Message};}
    }
    static List<SharedAdapterBackup> Sharing()
    {
        var json=NetworkSetup.Run("$s=New-Object -ComObject HNetCfg.HNetShare; $items=@(foreach($c in $s.EnumEveryConnection){$v=$s.INetSharingConfigurationForINetConnection($c);if($v.SharingEnabled){$p=$s.NetConnectionProps($c);[pscustomobject]@{Id=[string]$p.Guid;Role=[int]$v.SharingConnectionType;Virtual=([string]$p.DeviceName -match 'Wi-Fi Direct|Hosted Network')}}}); ConvertTo-Json -InputObject $items -Compress");
        return JsonSerializer.Deserialize<List<SharedAdapterBackup>>(json)??new();
    }
    public static async Task PrepareAsync(SessionState state,string? destination,CancellationToken token)
    {
        var saved=new HotspotBackup{Sharing=await Task.Run(Sharing,token)};
        NetworkOperatorTetheringManager? manager=null;
        try{var profile=Profile();if(profile!=null){manager=NetworkOperatorTetheringManager.CreateFromConnectionProfile(profile);saved.Enabled=manager.TetheringOperationalState==TetheringOperationalState.On;saved.ProfileAdapter=profile.NetworkAdapter?.NetworkAdapterId.ToString()??"";}}
        catch when(saved.Sharing.Count==0){}
        bool ownsTarget=saved.Sharing.Where(x=>x.Role==1).All(x=>destination==null?x.Virtual:x.Id.Trim('{','}').Equals(destination.Trim('{','}'),StringComparison.OrdinalIgnoreCase));
        if(saved.Sharing.Count>0&&!ownsTarget)throw new InvalidOperationException("An existing shared network uses another output. It cannot be replaced without disrupting that network.");
        if(!saved.Enabled&&saved.Sharing.Count==0)return;
        state.PreviousHotspot=saved;saved.Touched=true;NetworkSetup.Save(state);
        if(saved.Enabled){
            var result=await manager!.StopTetheringAsync();
            if(result.Status!=TetheringOperationStatus.Success)throw new InvalidOperationException("Windows could not stop the existing hotspot: "+result.Status);
            for(int attempt=0;attempt<20&&AdapterCatalog.Read().Any(a=>a.Connected&&a.Kind=="Hotspot virtual");attempt++)await Task.Delay(200,token);
        }
        await Task.Run(()=>NetworkSetup.Run("$s=New-Object -ComObject HNetCfg.HNetShare;foreach($c in $s.EnumEveryConnection){$v=$s.INetSharingConfigurationForINetConnection($c);if($v.SharingEnabled){$v.DisableSharing()}}"),token);
        token.ThrowIfCancellationRequested();
    }
    public static async Task RestoreAsync(SessionState state)
    {
        var previous=state.PreviousHotspot;if(previous is not{Touched:true})return;
        if(previous.Enabled){
            var profile=Profile(previous.ProfileAdapter)??throw new InvalidOperationException("Previous hotspot internet profile is unavailable. Recovery will retry next time.");
            var manager=NetworkOperatorTetheringManager.CreateFromConnectionProfile(profile);
            if(manager.TetheringOperationalState!=TetheringOperationalState.On){var result=await manager.StartTetheringAsync();if(result.Status!=TetheringOperationStatus.Success)throw new InvalidOperationException("Previous hotspot could not resume: "+result.Status);}
        }
        if(previous.Sharing.Count>0){
            string json=Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(previous.Sharing)));
            NetworkSetup.Run($"$old=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{json}')) | ConvertFrom-Json; $s=New-Object -ComObject HNetCfg.HNetShare;foreach($item in ($old|Sort-Object Role)){{$found=$false;foreach($c in $s.EnumEveryConnection){{$p=$s.NetConnectionProps($c);if([guid]$p.Guid -eq [guid]$item.Id){{$v=$s.INetSharingConfigurationForINetConnection($c);if(-not $v.SharingEnabled){{$v.EnableSharing([int]$item.Role)}};$found=$true;break}}}};if(-not $found){{throw 'Previous sharing adapter is temporarily unavailable'}}}}");
        }
        previous.Touched=false;NetworkSetup.Save(state);
    }
}
