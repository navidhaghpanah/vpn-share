using Windows.Devices.WiFiDirect;
using Windows.Security.Credentials;

namespace VpnShare;

public sealed class Hotspot : IDisposable
{
    WiFiDirectAdvertisementPublisher? publisher;
    WiFiDirectConnectionListener? listener;
    readonly List<WiFiDirectDevice> peers=new();
    bool stopping;
    public event Action<string>? Message;
    public async Task<AdapterInfo> StartAsync(string ssid,string password,CancellationToken token)
    {
        if(System.Text.Encoding.UTF8.GetByteCount(ssid) is <1 or >32) throw new ArgumentException("Wi-Fi name must contain 1 to 32 UTF-8 bytes.");
        if(password.Length is <8 or >63 || password.Any(c=>c<32 || c>126)) throw new ArgumentException("Use a Wi-Fi password with 8 to 63 printable English characters.");
        var before=AdapterCatalog.Read().Where(x=>x.Description.Contains("Wi-Fi Direct",StringComparison.OrdinalIgnoreCase) && x.Connected).Select(x=>x.Id).ToHashSet();
        if(before.Count>0) throw new InvalidOperationException("Another Wi-Fi Direct session or Mobile Hotspot is already active. VPN Share will not replace that session.");
        listener=new WiFiDirectConnectionListener();
        listener.ConnectionRequested+=OnRequest;
        publisher=new WiFiDirectAdvertisementPublisher();
        publisher.Advertisement.IsAutonomousGroupOwnerEnabled=true;
        publisher.Advertisement.LegacySettings.IsEnabled=true;
        publisher.Advertisement.LegacySettings.Ssid=ssid;
        publisher.Advertisement.LegacySettings.Passphrase=new PasswordCredential {Password=password};
        publisher.StatusChanged+=(_,e)=>Message?.Invoke($"Wi-Fi: {e.Status} ({e.Error})");
        publisher.Start();
        for(int i=0;i<100;i++) {
            token.ThrowIfCancellationRequested();
            if(publisher.Status==WiFiDirectAdvertisementPublisherStatus.Aborted)
                throw new InvalidOperationException("The Wi-Fi driver rejected hotspot creation. Check radio availability and Wi-Fi Direct support.");
            var candidates=AdapterCatalog.Read().Where(x=>x.Description.Contains("Wi-Fi Direct",StringComparison.OrdinalIgnoreCase) && x.Connected && !before.Contains(x.Id)).ToArray();
            if(publisher.Status==WiFiDirectAdvertisementPublisherStatus.Started && candidates.Length==1) return candidates[0];
            if(candidates.Length>1) throw new InvalidOperationException("Multiple Wi-Fi Direct interfaces appeared. Sharing stopped to avoid configuring the wrong adapter.");
            await Task.Delay(250,token);
        }
        throw new TimeoutException("Windows did not create a usable Wi-Fi Direct hotspot within 25 seconds.");
    }
    async void OnRequest(WiFiDirectConnectionListener sender,WiFiDirectConnectionRequestedEventArgs args)
    {
        try {
            using var request=args.GetConnectionRequest();
            var peer=await WiFiDirectDevice.FromIdAsync(request.DeviceInformation.Id);
            if(peer!=null)lock(peers){if(stopping)peer.Dispose();else peers.Add(peer);}
        } catch(Exception e) {Message?.Invoke("Wi-Fi client: "+e.Message);}
    }
    public void Dispose()
    {
        lock(peers)stopping=true;
        if(listener!=null) listener.ConnectionRequested-=OnRequest;
        publisher?.Stop();publisher=null;listener=null;
        lock(peers) {foreach(var peer in peers) peer.Dispose();peers.Clear();}
    }
}
