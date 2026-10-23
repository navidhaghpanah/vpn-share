using Windows.Devices.Enumeration;
using Windows.Devices.Radios;

namespace VpnShare;

public static class WifiRadios
{
    public static async Task Prepare(SessionState session,CancellationToken token)
    {
        var devices=await DeviceInformation.FindAllAsync(Radio.GetDeviceSelector());
        var radios=new List<(string Id,Radio Radio)>();
        foreach(var device in devices){var radio=await Radio.FromIdAsync(device.Id);if(radio?.Kind==RadioKind.WiFi)radios.Add((device.Id,radio));}
        if(radios.Count==0)throw new InvalidOperationException("No Wi-Fi radio is available. Attach or enable a supported Wi-Fi adapter.");
        var off=radios.Where(r=>r.Radio.State==RadioState.Off).ToArray();if(off.Length==0)return;
        var access=await Radio.RequestAccessAsync();if(access!=RadioAccessStatus.Allowed)throw new InvalidOperationException("Windows denied Wi-Fi radio access: "+access);
        foreach(var item in off){token.ThrowIfCancellationRequested();session.WifiRadios.Add(item.Id);NetworkSetup.Save(session);var result=await item.Radio.SetStateAsync(RadioState.On);if(result!=RadioAccessStatus.Allowed)throw new InvalidOperationException("Wi-Fi radio could not turn on: "+result);}
    }
    public static async Task Restore(SessionState session)
    {
        foreach(var id in session.WifiRadios.ToArray()){
            var radio=await Radio.FromIdAsync(id);if(radio==null)throw new InvalidOperationException("A changed Wi-Fi radio is unavailable for restoration.");
            if(radio.State!=RadioState.Off){var result=await radio.SetStateAsync(RadioState.Off);if(result!=RadioAccessStatus.Allowed)throw new InvalidOperationException("Wi-Fi radio restoration failed: "+result);}
            session.WifiRadios.Remove(id);NetworkSetup.Save(session);
        }
    }
}
