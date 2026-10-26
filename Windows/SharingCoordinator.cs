using System.Net;
using System.Security.Principal;

namespace VpnShare;

public sealed class SharingSession : IDisposable
{
    SessionState? state;
    Hotspot? hotspot;
    HostedHotspot? hosted;
    volatile IPacketEngine? nat;
    DhcpProtocol? dhcp;
    DnsProxy? dns;
    CancellationTokenSource? watchCancellation;
    Task? watcher;
    readonly SemaphoreSlim engineGate=new(1);
    string resolverOverride="";
    long previousUpload,previousDownload,previousDropped;
    bool active;
    public event Action<string>? Message;
    public bool Running=>active;
    public bool NeedsRecovery=>state!=null&&!active;
    public bool Connected=>active&&(nat?.Connected??false);
    public long Uploaded=>Interlocked.Read(ref previousUpload)+(nat?.Uploaded??0);
    public long Downloaded=>Interlocked.Read(ref previousDownload)+(nat?.Downloaded??0);
    public long Dropped=>Interlocked.Read(ref previousDropped)+(nat?.Dropped??0);
    public int Flows=>nat?.Flows??0;
    public Lease[] Clients=>dhcp?.Leases??Array.Empty<Lease>();
    public string? Gateway=>state?.Gateway;
    public static void Recover(){var prior=NetworkSetup.Load();if(prior!=null)NetworkSetup.Restore(prior);}
    public static string SelectHostedOutput(IEnumerable<string> capable,IEnumerable<AdapterInfo> adapters)
    {
        var ids=capable.Select(Guid.Parse).ToHashSet();
        var idle=adapters.Where(a=>HostedHotspot.CanUseAsOutput(a)&&ids.Contains(Guid.Parse(a.Id))).ToArray();
        return idle.Length==1?idle[0].Id:"";
    }
    static IPAddress Resolver(AdapterInfo source,string custom)
    {
        if(!string.IsNullOrWhiteSpace(custom)){
            if(!IPAddress.TryParse(custom,out var parsed)||parsed.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||IPAddress.IsLoopback(parsed)||parsed.Equals(IPAddress.Any))throw new ArgumentException("DNS must be a reachable IPv4 resolver.");
            return parsed;
        }
        return source.Dns.Select(IPAddress.Parse).FirstOrDefault(ip=>!IPAddress.IsLoopback(ip)&&!ip.Equals(IPAddress.Any))??IPAddress.Parse("1.1.1.1");
    }
    public async Task StartAsync(AdapterInfo source,AdapterInfo? destination,string ssid,string password,string resolver,CancellationToken token,string wifiOutput="")
    {
        if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("Run VPNShare.exe as Administrator.");
        if(state!=null)throw new InvalidOperationException("Stop the previous session first.");
        Message?.Invoke("Checking the personal-use packet driver…");
        await NdisDriverSetup.EnsureInstalled(token);
        source=AdapterCatalog.Read().FirstOrDefault(x=>x.Id==source.Id&&x.Connected)??throw new InvalidOperationException("The selected VPN is disconnected.");
        if(!source.IsVpn)throw new InvalidOperationException("A VPN tunnel adapter is required.");
        var vpnIp=AdapterCatalog.VpnAddress(source);
        if(!Routes.UsesInterface(IPAddress.Parse("1.1.1.1"),source.Index))throw new InvalidOperationException("Select the VPN carrying the default IPv4 route. Split-tunnel sharing is not supported by this engine.");
        var resolverIp=Resolver(source,resolver);
        if(!Routes.UsesInterface(resolverIp,source.Index))throw new InvalidOperationException("The DNS resolver must route through the selected VPN.");
        if(destination==null&&wifiOutput=="auto"){
            var candidates=HostedHotspot.CapableAdapters();
            wifiOutput=SelectHostedOutput(candidates,AdapterCatalog.Read());
        }
        await Task.Run(()=>{Recover();NetworkSetup.CheckConflicts();},token);
        try{
            var gateway=await Task.Run(NetworkSetup.ChooseGateway,token);
            state=new SessionState{VpnId=source.Id,VpnName=source.Name,VpnIndex=source.Index,VpnIp=vpnIp.ToString(),Gateway=gateway};
            RecoveryWatchdog.Start();
            if(destination==null)await WifiRadios.Prepare(state,token);
            await HotspotPlatform.PrepareAsync(state,destination?.Id,token);
            if(destination==null){
                Message?.Invoke("Creating your Wi-Fi network…");
                if(string.IsNullOrEmpty(wifiOutput)){
                    hotspot=new Hotspot();hotspot.Message+=x=>Message?.Invoke(x);
                    try{destination=await hotspot.StartAsync(ssid,password,token);}
                    catch(WifiDirectStartException original){
                        hotspot.Dispose();hotspot=null;
                        var fallback=SelectHostedOutput(HostedHotspot.CapableAdapters(),AdapterCatalog.Read());
                        if(string.IsNullOrEmpty(fallback))throw new InvalidOperationException("Wi-Fi Direct failed after bounded retries and no single idle Hosted AP adapter was available.",original);
                        Message?.Invoke("Wi-Fi Direct was rejected; falling back to the idle Hosted AP adapter…");
                        hosted=new HostedHotspot();hosted.Message+=x=>Message?.Invoke(x);destination=await hosted.StartAsync(fallback,ssid,password,state,token);
                        Message?.Invoke("Dedicated Wi-Fi AP fallback started. Incoming adapters were preserved.");
                    }
                }else{
                    hosted=new HostedHotspot();hosted.Message+=x=>Message?.Invoke(x);destination=await hosted.StartAsync(wifiOutput,ssid,password,state,token);
                    Message?.Invoke("Dedicated Wi-Fi AP started. Incoming adapters were preserved.");
                }
            }else{
                var wanted=destination.Id.Trim('{','}');
                destination=await Task.Run(()=>AdapterCatalog.Read().Concat(AdapterCatalog.ReadPhysicalDevices()).FirstOrDefault(x=>x.Id.Trim('{','}').Equals(wanted,StringComparison.OrdinalIgnoreCase)),token)??throw new InvalidOperationException("The Ethernet output adapter disappeared.");
                if(destination.Id==source.Id||destination.IsVpn||destination.Kind is "USB tethering" or "Wi-Fi"||destination.Gateways.Length>0)throw new InvalidOperationException("Choose an unused Ethernet adapter, not your incoming internet connection.");
            }
            state.AdapterId=destination.Id;state.AdapterName=destination.Name;state.DownstreamIndex=destination.Index;state.HotspotOwned=hotspot!=null||hosted!=null;
            var current=state;resolverOverride=resolver;
            await Task.Run(()=>{
                token.ThrowIfCancellationRequested();NetworkSetup.Snapshot(current);Guard.Install(current,()=>NetworkSetup.Save(current));
                token.ThrowIfCancellationRequested();Message?.Invoke("Preparing automatic addressing and protected DNS…");NetworkSetup.Configure(current);
                Message?.Invoke("Waiting for the hotspot gateway address to become usable…");NetworkSetup.WaitForGateway(current);
                token.ThrowIfCancellationRequested();
                dhcp=new DhcpProtocol(IPAddress.Parse(gateway),IPAddress.Parse(gateway));
                nat=EngineStartup.StartReady(()=>CreateEngine(source,current));
                dns=new DnsProxy(IPAddress.Parse(gateway),new(vpnIp,source.Index,resolverIp),()=>Connected);
                dns.Fault+=e=>Message?.Invoke("DNS service stopped: "+e.Message);
                dns.Start();
            },token);
            watchCancellation=new();watcher=Task.Run(()=>WatchAsync(watchCancellation.Token));
            active=true;
            Message?.Invoke("Sharing configured. Client traffic and leak prevention still require a live test.");
        }catch(Exception original){
            try{await Task.Run(Stop);}catch(Exception cleanup){throw new AggregateException("Sharing failed; network restoration needs attention.",original,cleanup);}
            throw;
        }
    }
    IPacketEngine CreateEngine(AdapterInfo source,SessionState current)
    {
        IPacketEngine engine=new NdisNatEngine(source,current,dhcp);engine.Message+=x=>Message?.Invoke(x);
        engine.Fault+=e=>Message?.Invoke("Packet engine stopped; client forwarding remains blocked: "+e.Message);return engine;
    }
    async Task WatchAsync(CancellationToken token)
    {
        while(!token.IsCancellationRequested){
            try{
                await Task.Delay(1000,token);var current=state;if(current==null)break;
                var connected=AdapterCatalog.Read().Where(x=>x.IsVpn&&x.Connected).ToArray();
                var candidate=connected.FirstOrDefault(x=>x.Id==current.VpnId)??connected.SingleOrDefault(x=>x.Name==current.VpnName);
                if(candidate==null||!Routes.UsesInterface(IPAddress.Parse("1.1.1.1"),candidate.Index))continue;
                string ip=AdapterCatalog.VpnAddress(candidate).ToString();
                if(nat!=null&&!nat.Faulted&&nat.Connected&&current.VpnIp==ip&&current.VpnIndex==candidate.Index)continue;
                await engineGate.WaitAsync(token);
                try{
                    NetworkSetup.SetForwarding(current,false);
                    DropEngine();
                    NdisRecovery.Restore(current);
                    current.VpnIp=ip;current.VpnIndex=candidate.Index;current.VpnId=candidate.Id;
                    NetworkSetup.Save(current);
                    Guard.InstallVpn(current,()=>NetworkSetup.Save(current));
                    var target=Resolver(candidate,resolverOverride);
                    if(!Routes.UsesInterface(target,candidate.Index))throw new InvalidOperationException("Reconnected VPN DNS is not inside the selected tunnel.");
                    dns?.Update(new(IPAddress.Parse(ip),candidate.Index,target));
                    nat=EngineStartup.StartReady(()=>CreateEngine(candidate,current));
                    // NDIS injects directly; host forwarding remains disabled.
                    Message?.Invoke("VPN packet interfaces reconnected. Client internet still needs verification on the connected device.");
                }finally{engineGate.Release();}
            }catch(OperationCanceledException)when(token.IsCancellationRequested){break;}
            catch(Exception e){Message?.Invoke("Reconnection is paused; client traffic remains blocked: "+e.Message);try{await Task.Delay(5000,token);}catch(OperationCanceledException){break;}}
        }
    }
    void DropEngine()
    {
        var old=nat;nat=null;if(old==null)return;
        Interlocked.Add(ref previousUpload,old.Uploaded);Interlocked.Add(ref previousDownload,old.Downloaded);Interlocked.Add(ref previousDropped,old.Dropped);old.Dispose();
    }
    public void Stop()
    {
        active=false;
        watchCancellation?.Cancel();
        engineGate.Wait();
        try{
            if(state is{NetworkTouched:true})NetworkSetup.SetForwarding(state,false);
            dhcp=null;dns?.Dispose();dns=null;
            // Dispose releases the old device even when restoring its stale binding fails.
            // Always attempt journal recovery with a fresh device afterwards.
            StopRecovery.Run(DropEngine,()=>{
                if(state!=null)NetworkSetup.Restore(state,()=>{hotspot?.Dispose();hotspot=null;hosted?.Dispose();hosted=null;});
            });
            state=null;
            hotspot?.Dispose();hotspot=null;
            hosted?.Dispose();hosted=null;
        }finally{engineGate.Release();}
        watcher?.Wait(TimeSpan.FromSeconds(3));watcher=null;watchCancellation?.Dispose();watchCancellation=null;
        Message?.Invoke("Sharing stopped. Network settings restored.");
    }
    public void Dispose()=>Stop();
}
