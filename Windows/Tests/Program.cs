using System.Net;
using System.Runtime.InteropServices;
using VpnShare;
using System.Net.NetworkInformation;
using System.Net.Sockets;

int passed=0;
void Assert(bool value,string message){if(!value)throw new Exception("FAIL: "+message);Console.WriteLine("PASS: "+message);passed++;}
byte[] Request(byte message,byte[]? extra=null)
{
    var b=new byte[300];b[0]=1;b[1]=1;b[2]=6;b[28]=2;b[33]=1;
    Packets.Put32(b,4,0x12345678);Packets.Put32(b,236,0x63825363);
    b[240]=53;b[241]=1;b[242]=message;
    if(extra!=null)Array.Copy(extra,0,b,243,extra.Length);
    b[243+(extra?.Length??0)]=255;return b;
}
byte[] Option(byte[] b,byte key)
{
    for(int p=240;p<b.Length;){byte kind=b[p++];if(kind==255)break;if(kind==0)continue;int n=b[p++];if(kind==key)return b.AsSpan(p,n).ToArray();p+=n;}
    return Array.Empty<byte>();
}
var gateway=IPAddress.Parse("10.203.91.1");var dns=IPAddress.Parse("1.1.1.1");
var dhcp=new DhcpProtocol(gateway,dns);
var discover=Request(1);var offer=dhcp.Reply(discover)!;
Assert(offer!=null && offer[0]==2 && Option(offer,53).SequenceEqual(new byte[]{2}),"DHCP DISCOVER produces OFFER");
Assert(Packets.U32(offer!,4)==0x12345678,"DHCP preserves transaction identifier");
uint leased=Packets.U32(offer!,16);
Assert((leased&0xffffff00)==Packets.Ip(gateway)-1 && (leased&255)>=20,"DHCP allocates inside private client pool");
Assert(Packets.U32(dhcp.Reply(discover)!,16)==leased,"DHCP repeated DISCOVER keeps the same lease");
var request=Request(3,new byte[]{50,4,(byte)(leased>>24),(byte)(leased>>16),(byte)(leased>>8),(byte)leased});
Assert(Option(dhcp.Reply(request)!,53)[0]==5,"DHCP REQUEST confirms the offered lease");
Assert(Option(offer!,6).SequenceEqual(dns.GetAddressBytes()),"DHCP advertises the VPN-routed DNS resolver");
Assert(Option(offer!,3).SequenceEqual(gateway.GetAddressBytes()),"DHCP advertises app gateway");
Assert(dhcp.Reply(Request(3,new byte[]{54,4,192,168,1,1}))==null,"DHCP ignores another server's REQUEST");
Assert(Option(dhcp.Reply(Request(3,new byte[]{50,4,10,203,91,240}))!,53)[0]==6,"DHCP rejects an unallocated requested address");
Assert(dhcp.Reply(Request(7))==null && dhcp.Leases.Length==0,"DHCP RELEASE frees the lease");
discover[2]=20;Assert(dhcp.Reply(discover)==null,"DHCP rejects invalid hardware address length");
discover=Request(1);discover[243]=70;discover[244]=255;Assert(dhcp.Reply(discover)==null,"DHCP rejects truncated options");
discover=Request(1);Packets.Put32(discover,24,Packets.Ip(IPAddress.Parse("192.168.1.1")));Assert(dhcp.Reply(discover)==null,"DHCP rejects off-interface relayed requests");
for(int i=0;i<200;i++){var r=Request(1);r[32]=(byte)(i>>8);r[33]=(byte)i;AssertOffer(r);}
void AssertOffer(byte[] r){if(dhcp.Reply(r)==null)throw new Exception("Pool allocation failed");}
var exhausted=Request(1);exhausted[31]=1;
Assert(dhcp.Reply(exhausted)==null && dhcp.Leases.Length==200,"DHCP pool exhaustion is bounded and does not duplicate leases");

byte[] udp=new byte[33];udp[0]=0x45;udp[8]=64;udp[9]=17;Packets.Put16(udp,2,(ushort)udp.Length);
Packets.Put32(udp,12,Packets.Ip(IPAddress.Parse("10.203.91.20")));Packets.Put32(udp,16,Packets.Ip(dns));
Packets.Put16(udp,20,53001);Packets.Put16(udp,22,53);Packets.Put16(udp,24,13);udp[28]=1;udp[32]=99;
Packets.FixChecksums(udp,20,udp.Length);
Assert(Packets.Parse(udp,udp.Length,out var header,out var total) && header==20 && total==udp.Length,"IPv4 parser accepts a valid odd-length UDP packet");
Assert(Packets.Checksum(udp.AsSpan(0,20))==0,"IPv4 checksum is valid");
uint seed=(uint)(Packets.U16(udp,12)+Packets.U16(udp,14)+Packets.U16(udp,16)+Packets.U16(udp,18)+17+udp.Length-20);
Assert(Packets.Checksum(udp.AsSpan(20),seed)==0,"UDP pseudo-header checksum is valid");
udp[6]=0x20;Assert(!Packets.Parse(udp,udp.Length,out _,out _),"Fragmented traffic is rejected rather than mis-translated");udp[6]=0;
Assert(!Packets.Parse(udp,udp.Length-1,out _,out _),"Truncated IPv4 payload is rejected");
Packets.Put16(udp,24,8);Assert(!Packets.Parse(udp,udp.Length,out _,out _),"Inconsistent UDP length is rejected");
var tcp=new byte[44];tcp[0]=0x45;tcp[8]=64;tcp[9]=6;Packets.Put16(tcp,2,44);tcp[32]=0x60;tcp[33]=2;tcp[40]=2;tcp[41]=4;Packets.Put16(tcp,42,1460);
Packets.ClampMss(tcp,20,tcp.Length,1240);
Assert(Packets.U16(tcp,42)==1240,"TCP SYN MSS is clamped to tunnel MTU");

using var table=new NatTable((_,_)=>null);
var key=new FlowKey(6,Packets.Ip(gateway)+19,12345,Packets.Ip(dns),443);
var flow=table.GetOrCreate(key)!;
Assert(table.GetOrCreate(key)!.Port==flow.Port && table.Count==1,"NAT reuses a mapping for an existing flow");
Assert(table.Find(6,flow.Port,key.Remote,443)==flow,"NAT reverses the matching remote endpoint");
Assert(table.Find(6,flow.Port,key.Remote+1,443)==null && table.Find(6,flow.Port,key.Remote,80)==null,"NAT refuses a spoofed remote endpoint");
Assert(table.GetOrCreate(key with {Client=key.Client+1})!.Port!=flow.Port,"NAT isolates clients using the same source port");
table.Expire(Environment.TickCount64+600001);
Assert(table.Count==0,"NAT idle mappings expire");
var filterType=typeof(Guard).GetNestedType("Filter0",System.Reflection.BindingFlags.NonPublic)!;
Assert(Marshal.SizeOf(filterType)==200 && Marshal.OffsetOf(filterType,"Conditions").ToInt32()==120 && Marshal.OffsetOf(filterType,"EffectiveWeight").ToInt32()==184,"WFP filter ABI matches Windows x64 structure layout");
Assert(SubnetSelector.Choose(new[]{"0.0.0.0/1","128.0.0.0/1"})=="10.203.91.1","Subnet selection allows full-tunnel aggregate routes");
Assert(SubnetSelector.Choose(new[]{"10.203.91.0/24"})=="10.204.91.1","Subnet selection avoids a connected client network");
Assert(SubnetSelector.Choose(new[]{"10.0.0.0/8"})=="172.29.200.1","Subnet selection falls back when the 10/8 range is occupied");
var upstreamSummaries=new[]{new SubnetRoute("10.0.0.0/8","172.31.80.1"),new SubnetRoute("172.16.0.0/12","172.31.80.1"),new SubnetRoute("192.168.0.0/16","172.31.80.1"),new SubnetRoute("172.31.80.0/24","0.0.0.0")};
Assert(SubnetSelector.ChooseRoutes(upstreamSummaries)=="10.203.91.1","Forwarded RFC1918 summary routes from an upstream router do not exhaust every private pool");
Assert(SubnetSelector.ChooseRoutes(upstreamSummaries.Append(new("10.203.91.0/24","172.31.80.1")))=="10.204.91.1","A specific routed private subnet remains protected despite broader upstream summaries");
Assert(SubnetSelector.ChooseRoutes(new[]{new SubnetRoute("10.0.0.0/8","0.0.0.0")})=="172.29.200.1","An on-link private aggregate remains occupied and is never ignored");
Assert(SubnetSelector.ChooseRoutes(new[]{new SubnetRoute("10.128.0.0/9","172.31.80.1")})=="172.29.200.1","Ordinary routed private prefixes are preserved; only exact RFC1918 summaries are exempted");
Assert(SubnetSelector.ChooseRoutes(new[]{new SubnetRoute("10.0.0.0/8","invalid")})=="172.29.200.1","Unknown next-hop metadata cannot exempt an occupied private network");
bool noPrivatePool=false;
try{SubnetSelector.ChooseRoutes(new[]{new SubnetRoute("10.0.0.0/8","0.0.0.0"),new SubnetRoute("172.16.0.0/12","0.0.0.0"),new SubnetRoute("192.168.0.0/16","0.0.0.0")});}catch(InvalidOperationException){noPrivatePool=true;}
Assert(noPrivatePool,"All truly on-link private ranges still produce a conflict instead of an overlapping gateway");
Assert(ExternalVpnStatus.ParseExpressVpn("Connected to test-location\r\n\r\nProtocol in use: WireGuard\r\n") is{Provider:"ExpressVPN",Protocol:"WireGuard"},"Vendor CLI status detects a connected adapterless ExpressVPN without inventing a tunnel interface");
Assert(ExternalVpnStatus.ParseExpressVpn("Disconnected\nProtocol in use: WireGuard\n")==null,"Disconnected vendor status is never classified as connected");
Assert(ExternalVpnStatus.ParseExpressVpn("Connecting\nProtocol in use: LightwayTcp\n")==null,"An in-progress vendor connection is not reported as connected");
Assert(ExternalVpnStatus.ParseExpressVpn("Not Connected to a server\n")==null,"A substring mentioning Connected is not accepted as a VPN state");
Assert(ExternalVpnStatus.ParseExpressVpn("Connected to test-location\n") is{Protocol:"unknown protocol"},"A connected vendor with missing protocol metadata remains explicit about the unknown protocol");
byte[] query=new byte[]{0x71,0x23,1,0,0,1,0,0,0,0,0,0,7,(byte)'e',(byte)'x',(byte)'a',(byte)'m',(byte)'p',(byte)'l',(byte)'e',3,(byte)'c',(byte)'o',(byte)'m',0,0,1,0,1};
Assert(DnsWire.IsQuery(query),"DNS validates a complete standard question");
Assert(!DnsWire.IsQuery(query.AsSpan(0,12)),"DNS rejects a question missing its name and type");
var cycle=new byte[18];cycle[5]=1;cycle[12]=0xc0;cycle[13]=12;
Assert(!DnsWire.IsQuery(cycle),"DNS rejects compression-pointer cycles");
var answer=(byte[])query.Clone();answer[2]|=128;
Assert(DnsWire.Matches(query,answer),"DNS accepts a matching response identifier");answer[1]++;
Assert(!DnsWire.Matches(query,answer),"DNS rejects mismatched transaction identifiers");

// Custom NDIS NAT is exercised without loading a kernel driver.
byte[] Datagram(uint from,uint to,ushort fromPort,ushort toPort,int size=32){
    var b=new byte[size];b[0]=0x45;b[8]=64;b[9]=17;Packets.Put16(b,2,(ushort)size);Packets.Put32(b,12,from);Packets.Put32(b,16,to);Packets.Put16(b,20,fromPort);Packets.Put16(b,22,toPort);Packets.Put16(b,24,(ushort)(size-20));Packets.FixChecksums(b,20,size);return b;
}
uint clientIp=Packets.Ip(gateway)+19,vpnIp=Packets.Ip(IPAddress.Parse("10.8.0.5")),remoteIp=Packets.Ip(dns);
bool routeAllowed=true;
using(var ndisNat=new NdisNatProtocol(vpnIp,Packets.Ip(gateway),1280,(_,_)=>null,_=>routeAllowed)){
    var outbound=Datagram(clientIp,remoteIp,12345,443);
    Assert(ndisNat.Outbound(outbound,true,out _)&&Packets.U32(outbound,12)==vpnIp&&outbound[8]==63,"NDIS custom NAT translates outbound source and decrements TTL");
    ushort mapped=Packets.U16(outbound,20);
    Assert(Packets.Checksum(outbound.AsSpan(0,20))==0,"NDIS translated outbound IPv4 checksum is valid");
    var inbound=Datagram(remoteIp,vpnIp,443,mapped);
    Assert(ndisNat.Inbound(inbound,true)==1&&Packets.U32(inbound,16)==clientIp&&Packets.U16(inbound,22)==12345&&inbound[8]==63,"NDIS reverse NAT restores the original client endpoint");
    uint pseudo=(uint)(Packets.U16(inbound,12)+Packets.U16(inbound,14)+Packets.U16(inbound,16)+Packets.U16(inbound,18)+17+inbound.Length-20);
    Assert(Packets.Checksum(inbound.AsSpan(20),pseudo)==0,"NDIS reverse NAT recalculates the UDP checksum");
    Assert(ndisNat.Inbound(Datagram(remoteIp+1,vpnIp,443,mapped),true)==0,"NDIS NAT refuses a reverse packet from another remote endpoint");
    Assert(ndisNat.Inbound(Datagram(remoteIp,vpnIp,443,mapped),false)==-1,"NDIS NAT consumes matching replies while the VPN gate is closed");
    Assert(!ndisNat.Outbound(Datagram(clientIp,remoteIp,1000,443),false,out _),"NDIS NAT never creates a flow while disconnected");
    routeAllowed=false;Assert(!ndisNat.Outbound(Datagram(clientIp,remoteIp,1001,443),true,out _),"NDIS NAT rejects destinations routed outside the selected VPN");routeAllowed=true;
    Assert(!ndisNat.Outbound(Datagram(clientIp+256,remoteIp,1002,443),true,out _),"NDIS NAT rejects an off-subnet source address");
    Assert(!ndisNat.Outbound(Datagram(clientIp,remoteIp,1003,443,1300),true,out var tooBig)&&tooBig!=null&&tooBig[20]==3&&tooBig[21]==4&&Packets.U16(tooBig,26)==1280,"NDIS NAT returns ICMP fragmentation-needed with the tunnel MTU");
    var fragment=Datagram(clientIp,remoteIp,1004,443);fragment[6]=0x20;
    Assert(!ndisNat.Outbound(fragment,true,out _),"NDIS NAT rejects fragmented client traffic");
    ndisNat.Clear();Assert(ndisNat.Inbound(Datagram(remoteIp,vpnIp,443,mapped),true)==0&&ndisNat.Flows==0,"NDIS NAT invalidates old mappings after tunnel loss");
}
var adapterBytes=new byte[NdisDevice.AdapterListBytes];BitConverter.GetBytes(1u).CopyTo(adapterBytes,0);System.Text.Encoding.ASCII.GetBytes("\\DEVICE\\{TEST}").CopyTo(adapterBytes,4);BitConverter.GetBytes(0x123456789L).CopyTo(adapterBytes,8196);new byte[]{2,3,4,5,6,7}.CopyTo(adapterBytes,8580);BitConverter.GetBytes((ushort)1500).CopyTo(adapterBytes,8772);
var parsedAdapters=NdisDevice.ParseAdapters(adapterBytes);
Assert(parsedAdapters.Length==1&&parsedAdapters[0].Handle==0x123456789L&&parsedAdapters[0].Mtu==1500&&parsedAdapters[0].Mac[5]==7,"NDIS x64 adapter list decoding matches the published packed ABI");
BitConverter.GetBytes(19u).CopyTo(adapterBytes,8452);
Assert(NdisDevice.ParseAdapters(adapterBytes)[0].Medium==19,"NDIS identifies an IP tunnel separately from an Ethernet adapter");
var hostedSettings=HostedHotspot.ConnectionSettings("Navid VPN");
Assert(hostedSettings.Length==40&&BitConverter.ToUInt32(hostedSettings)==9&&BitConverter.ToUInt32(hostedSettings,36)==32,"Hosted AP settings preserve the UTF-8 SSID length and bounded peer limit");
bool longSsid=false;try{HostedHotspot.ConnectionSettings(new string('x',33));}catch(ArgumentException){longSsid=true;}
Assert(longSsid,"Hosted AP rejects oversized SSIDs before calling Windows");
var ownedId=Guid.NewGuid();
var ownedAp=new SessionState{AdapterId=ownedId.ToString(),HotspotOwned=true,HostedSettings=new HostedSettingsBackup{OwnedAdapterId=ownedId.ToString(),ExpectedConnection=HostedHotspot.ConnectionSettings("Acceptance AP"),StartRequested=true}};
Assert(HostedHotspot.CanStopOwned(ownedAp,ownedId,HostedHotspot.ConnectionSettings("Acceptance AP"),"ignored"),"Recovery may stop the retained AP matching its journaled interface and SSID");
Assert(!HostedHotspot.CanStopOwned(ownedAp,Guid.NewGuid(),HostedHotspot.ConnectionSettings("Acceptance AP"),"ignored"),"Recovery refuses an unrelated active AP interface");
Assert(!HostedHotspot.CanStopOwned(ownedAp,ownedId,HostedHotspot.ConnectionSettings("Another AP"),"ignored"),"Recovery refuses an active AP whose SSID changed");
var legacyAp=new SessionState{AdapterId=ownedId.ToString(),HotspotOwned=true,HostedSettings=new HostedSettingsBackup()};
Assert(HostedHotspot.CanStopOwned(legacyAp,ownedId,HostedHotspot.ConnectionSettings("Legacy AP"),"Legacy AP"),"Legacy recovery requires the recorded interface and saved widget SSID");
Assert(!HostedHotspot.CanStopOwned(legacyAp,ownedId,HostedHotspot.ConnectionSettings("Another AP"),"Legacy AP"),"Legacy recovery cannot stop an AP with another network name");
legacyAp.HotspotOwned=false;
Assert(!HostedHotspot.CanStopOwned(legacyAp,ownedId,HostedHotspot.ConnectionSettings("Legacy AP"),"Legacy AP"),"A journal without AP ownership cannot authorize force stop");
BitConverter.GetBytes(33u).CopyTo(adapterBytes,0);bool oversized=false;try{NdisDevice.ParseAdapters(adapterBytes);}catch(InvalidDataException){oversized=true;}
Assert(oversized,"NDIS adapter decoder rejects oversized kernel counts");
Assert(NdisDevice.Code(4)==0x830020d0&&NdisDevice.BufferHeader==52,"NDIS packet IOCTL and x64 frame offset match the SDK");
var ethernet=NdisNatEngine.Frame(new byte[]{0x45,0},new byte[]{2,3,4,5,6,7},new byte[]{8,9,10,11,12,13});
Assert(ethernet[0]==8&&ethernet[6]==2&&ethernet[12]==8&&ethernet[13]==0&&ethernet[14]==0x45,"NDIS injection builds explicit Ethernet source, destination and IPv4 type");

var rawDiscover=Datagram(0,uint.MaxValue,68,67,328);Request(1).CopyTo(rawDiscover,28);Packets.FixChecksums(rawDiscover,20,rawDiscover.Length);
var clientMac=Request(1).AsSpan(28,6).ToArray();var frameDhcp=new DhcpProtocol(gateway,gateway);
Assert(NdisDhcp.Handle(frameDhcp,rawDiscover,clientMac,Packets.Ip(gateway),out var rawOffer)&&rawOffer!=null,"NDIS DHCP consumes a client DISCOVER and builds an OFFER without a UDP server socket");
Assert(rawOffer!=null&&Packets.U16(rawOffer,20)==67&&Packets.U16(rawOffer,22)==68&&Packets.U32(rawOffer,16)==uint.MaxValue,"NDIS DHCP response uses server/client ports and broadcast destination");
Assert(rawOffer!=null&&Packets.Checksum(rawOffer.AsSpan(0,20))==0,"NDIS DHCP response has a valid IPv4 checksum");
Assert(NdisDhcp.Handle(frameDhcp,rawDiscover,new byte[]{9,9,9,9,9,9},Packets.Ip(gateway),out var spoofedOffer)&&spoofedOffer==null,"NDIS DHCP consumes and rejects a BOOTP hardware address mismatch");
Assert(!NdisDhcp.Handle(frameDhcp,Datagram(clientIp,Packets.Ip(gateway),12345,53),clientMac,Packets.Ip(gateway),out _),"NDIS DHCP leaves ordinary gateway DNS traffic for the DNS proxy");

// Read-only integration regression for the actual CIM GUID/string mismatch.
var realAdapter=AdapterCatalog.Read().First(a=>!a.IsVpn&&a.Gateways.Length>0);
Assert(IPAddress.TryParse(NetworkSetup.ChooseGateway(),out _),"Live read-only route metadata selects a gateway even when USB tethering advertises RFC1918 summaries");
using(var snapshot=System.Text.Json.JsonDocument.Parse(NetworkSetup.CaptureAdapterConfiguration(realAdapter.Id))){
    Assert(snapshot.RootElement.GetProperty("Mtu").GetInt32()>0,"Windows snapshot finds a real CIM adapter by its brace-wrapped GUID");
    Assert(snapshot.RootElement.GetProperty("Addresses").GetArrayLength()>0,"Windows snapshot reads real adapter addresses without modifying them");
}

string shadowDirectory=Path.Combine(Path.GetTempPath(),"vpnshare-shadow-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(shadowDirectory);
string originalDirectory=Environment.CurrentDirectory;
try{
    File.WriteAllText(Path.Combine(shadowDirectory,"powershell.exe"),"not an executable");Environment.CurrentDirectory=shadowDirectory;
    Assert(NetworkSetup.Run("Write-Output 'trusted-system-helper'")=="trusted-system-helper","Privileged helper resolution ignores a same-name file in a writable working directory");
}finally{Environment.CurrentDirectory=originalDirectory;File.Delete(Path.Combine(shadowDirectory,"powershell.exe"));Directory.Delete(shadowDirectory);}
bool tamperedRejected=false;try{using var changed=new MemoryStream(new byte[]{1,2,3,4});NdisDriverSetup.VerifyDigest(changed);}catch(InvalidDataException){tamperedRejected=true;}
Assert(tamperedRejected,"Driver installer rejects bytes that do not match the pinned digest");

// Loopback-only integration checks use ephemeral UDP/TCP ports, not host port 53.
using var testCancel=new CancellationTokenSource();
using var resolverSocket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
resolverSocket.Bind(new IPEndPoint(IPAddress.Loopback,0));int resolverPort=((IPEndPoint)resolverSocket.LocalEndPoint!).Port;
var resolverTcp=new TcpListener(IPAddress.Loopback,resolverPort);resolverTcp.Start();
int requests=0;bool corrupt=false;
Assert(NetworkSetup.Run("Get-Item -LiteralPath 'Z:\\VPNShare-missing-regression-probe' -ErrorAction SilentlyContinue")=="","Handled missing recovery objects do not produce a false helper failure");
bool helperThrows=false;try{NetworkSetup.Run("throw 'restore-regression-marker'");}catch(InvalidOperationException e){helperThrows=e.Message.Contains("restore-regression-marker");}
Assert(helperThrows,"Terminating recovery errors retain their diagnostic text");
var udpResolver=Task.Run(async()=>{
    try{var b=new byte[4096];while(!testCancel.IsCancellationRequested){
        var got=await resolverSocket.ReceiveFromAsync(b,SocketFlags.None,new IPEndPoint(IPAddress.Any,0),testCancel.Token);Interlocked.Increment(ref requests);
        var reply=b.AsSpan(0,got.ReceivedBytes).ToArray();reply[2]|=128;if(corrupt)reply[1]++;
        await resolverSocket.SendToAsync(reply,SocketFlags.None,got.RemoteEndPoint,testCancel.Token);
    }}catch(Exception e)when(testCancel.IsCancellationRequested&&e is SocketException or OperationCanceledException or ObjectDisposedException){}
});
var tcpResolver=Task.Run(async()=>{
    try{while(!testCancel.IsCancellationRequested){
        using var client=await resolverTcp.AcceptTcpClientAsync(testCancel.Token);var s=client.GetStream();var h=new byte[2];await s.ReadExactlyAsync(h,testCancel.Token);var q=new byte[h[0]*256+h[1]];await s.ReadExactlyAsync(q,testCancel.Token);q[2]|=128;
        await s.WriteAsync(h,testCancel.Token);await s.WriteAsync(q,testCancel.Token);
    }}catch(Exception e)when(testCancel.IsCancellationRequested&&e is SocketException or OperationCanceledException or ObjectDisposedException){}
});
var loop=NetworkInterface.GetAllNetworkInterfaces().First(x=>x.NetworkInterfaceType==NetworkInterfaceType.Loopback).GetIPProperties().GetIPv4Properties().Index;
bool vpnAllowed=true;
using(var proxy=new DnsProxy(IPAddress.Loopback,new(IPAddress.Loopback,loop,IPAddress.Loopback,resolverPort),()=>vpnAllowed,0)){
    proxy.Start();
    using var client=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);await client.ConnectAsync(IPAddress.Loopback,proxy.Port);
    await client.SendAsync(query);var reply=new byte[4096];using(var timeout=new CancellationTokenSource(3000)){
        int count=await client.ReceiveAsync(reply,SocketFlags.None,timeout.Token);
        Assert(DnsWire.Matches(query,reply.AsSpan(0,count)),"DNS UDP proxy relays a real loopback query through its pinned interface");
    }
    using(var clientTcp=new TcpClient()){
        await clientTcp.ConnectAsync(IPAddress.Loopback,proxy.Port);var stream=clientTcp.GetStream();var h=new byte[]{0,(byte)query.Length};
        await stream.WriteAsync(h.AsMemory(0,1));await stream.WriteAsync(h.AsMemory(1,1));await stream.WriteAsync(query);
        using var timeout=new CancellationTokenSource(3000);await stream.ReadExactlyAsync(h,timeout.Token);var q=new byte[h[0]*256+h[1]];await stream.ReadExactlyAsync(q,timeout.Token);
        Assert(DnsWire.Matches(query,q),"DNS TCP proxy handles a split length header and returns the matching frame");
    }
    vpnAllowed=false;int before=Volatile.Read(ref requests);await client.SendAsync(query);bool blocked=false;
    using(var timeout=new CancellationTokenSource(250)){try{await client.ReceiveAsync(reply,SocketFlags.None,timeout.Token);}catch(OperationCanceledException){blocked=true;}}
    Assert(blocked&&Volatile.Read(ref requests)==before,"DNS sends no upstream request while the VPN gate is closed");
    vpnAllowed=true;corrupt=true;await client.SendAsync(query);bool discarded=false;
    using(var timeout=new CancellationTokenSource(350)){try{await client.ReceiveAsync(reply,SocketFlags.None,timeout.Token);}catch(OperationCanceledException){discarded=true;}}
    Assert(discarded,"DNS proxy discards a real upstream datagram with the wrong transaction identifier");
}
testCancel.Cancel();resolverSocket.Dispose();resolverTcp.Stop();await Task.WhenAll(udpResolver,tcpResolver);
var readyEngine=new FakePacketEngine(true);
Assert(ReferenceEquals(EngineStartup.StartReady(()=>readyEngine),readyEngine)&&!readyEngine.Disposed,"Ready packet engine is published only after its connection gate is open");
readyEngine.Dispose();
var waitingEngine=new FakePacketEngine(false);bool waitingRejected=false;
try{EngineStartup.StartReady(()=>waitingEngine);}catch(InvalidOperationException){waitingRejected=true;}
Assert(waitingRejected&&waitingEngine.Disposed,"Disconnected replacement is disposed and cannot report successful reconnection");
var failedEngine=new FakePacketEngine(true){Faulted=true};bool failedRejected=false;
try{EngineStartup.StartReady(()=>failedEngine);}catch(InvalidOperationException){failedRejected=true;}
Assert(failedRejected&&failedEngine.Disposed,"A faulted replacement cannot be published even when Connected is true");
var dirtyEngine=new FakePacketEngine(false){FailDispose=true};bool bothErrors=false;
try{EngineStartup.StartReady(()=>dirtyEngine);}catch(AggregateException e){bothErrors=e.InnerExceptions.Count==2;}
Assert(bothErrors,"Failed startup retains both the readiness failure and cleanup failure");

var binding=new NdisAdapter(101,"test-binding",new byte[6],1500);
SessionState Journal(long handle)=>new(){NdisInterfaces=new(){binding.Name},NdisHandles=new(){{binding.Name,handle}}};
var removedBinding=Journal(101);int touchedBindings=0;
NdisRecovery.Restore(removedBinding,Array.Empty<NdisAdapter>(),_=>throw new Exception("Absent binding was queried"),(_,_)=>touchedBindings++,()=>{});
Assert(removedBinding.NdisInterfaces.Count==0&&removedBinding.NdisHandles.Count==0&&touchedBindings==0,"A removed VPN binding is retired without IOCTLs on its stale handle");
var replacedBinding=Journal(100);
NdisRecovery.Restore(replacedBinding,new[]{binding},_=>throw new Exception("Replacement binding was queried"),(_,_)=>touchedBindings++,()=>{});
Assert(replacedBinding.NdisInterfaces.Count==0&&touchedBindings==0,"A same-name replacement binding is not reset because it may belong to another filter");
var ownedBinding=Journal(101);uint restoredMode=99;int persistedBindings=0;
NdisRecovery.Restore(ownedBinding,new[]{binding},_=>2,(_,mode)=>restoredMode=mode,()=>persistedBindings++);
Assert(restoredMode==0&&persistedBindings==1&&ownedBinding.NdisInterfaces.Count==0,"The owned live binding is reset and journaled using its freshly enumerated handle");
var pendingBinding=Journal(101);bool resetFailed=false;
try{NdisRecovery.Restore(pendingBinding,new[]{binding},_=>2,(_,_)=>throw new IOException("reset unavailable"),()=>{});}catch(InvalidOperationException){resetFailed=true;}
Assert(resetFailed&&pendingBinding.NdisInterfaces.Count==1&&pendingBinding.NdisHandles.Count==1,"A failed mode reset preserves binding ownership for a later recovery attempt");
NdisRecovery.Restore(pendingBinding,new[]{binding},_=>0,(_,_)=>throw new Exception("Idle binding was reset"),()=>{});
Assert(pendingBinding.NdisInterfaces.Count==0,"Retry retires a binding that the driver has already returned to normal mode");
var unrelatedBinding=Journal(101);bool unrelatedRejected=false;
try{NdisRecovery.Restore(unrelatedBinding,new[]{binding},_=>4,(_,_)=>throw new Exception("Unrelated mode was changed"),()=>{});}catch(InvalidOperationException){unrelatedRejected=true;}
Assert(unrelatedRejected&&unrelatedBinding.NdisInterfaces.Count==1,"Unexpected filter modes remain untouched and retain the recovery journal");
var unknownAp=new SessionState{HostedSettings=new(){StartRequested=true,ExpectedConnection=HostedHotspot.ConnectionSettings("Pending AP")}};
Assert(!HostedHotspot.CanStopOwned(unknownAp,Guid.NewGuid(),HostedHotspot.ConnectionSettings("Pending AP"),"Pending AP"),"An AP without a captured active interface cannot authorize a forced stop");

int restoredAfterFailure=0;
StopRecovery.Run(()=>throw new InvalidOperationException("stale device"),()=>restoredAfterFailure++);
Assert(restoredAfterFailure==1,"Shutdown retries journal recovery after engine disposal failure");
var shutdownOrder=new List<int>();
StopRecovery.Run(()=>shutdownOrder.Add(1),()=>shutdownOrder.Add(2));
Assert(shutdownOrder.SequenceEqual(new[]{1,2}),"Engine is released before opening recovery device");
bool bothErrorsRetained=false;
try{StopRecovery.Run(()=>throw new InvalidOperationException("release"),()=>throw new IOException("restore"));}
catch(AggregateException e){bothErrorsRetained=e.InnerExceptions.Count==2;}
Assert(bothErrorsRetained,"Failed shutdown preserves both recovery errors");
bool recoveryFailureRetained=false;
try{StopRecovery.Run(()=>{},()=>throw new IOException("restore"));}catch(IOException){recoveryFailureRetained=true;}
Assert(recoveryFailureRetained,"Journal restoration failure is never reported as success");

Assert(!Hotspot.NeedsStop(Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus.Aborted),"Aborted Wi-Fi Direct publisher is released without invalid Stop");
Assert(!Hotspot.NeedsStop(Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus.Created),"Unstarted publisher needs no Stop");
Assert(!Hotspot.NeedsStop(Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus.Stopped),"Stopped publisher cleanup is idempotent");
Assert(Hotspot.NeedsStop(Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus.Started),"Active publisher is stopped before release");
Assert(Hotspot.ShouldRetryStart(Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus.Aborted,Windows.Devices.WiFiDirect.WiFiDirectError.Success,0),"Aborted (Success) receives a bounded Wi-Fi Direct retry");
Assert(!Hotspot.ShouldRetryStart(Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus.Aborted,Windows.Devices.WiFiDirect.WiFiDirectError.Success,2),"Wi-Fi Direct retry is bounded");
Assert(!Hotspot.ShouldRetryStart(Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus.Aborted,Windows.Devices.WiFiDirect.WiFiDirectError.RadioNotAvailable,0),"A real radio failure is not retried as success");
var idleWifi=new AdapterInfo(Guid.NewGuid().ToString(),"Output","Wi-Fi",42,"Wi-Fi",false,Array.Empty<string>(),Array.Empty<string>(),Array.Empty<string>(),1500);
Assert(SharingSession.SelectHostedOutput(new[]{idleWifi.Id},new[]{idleWifi})==idleWifi.Id,"Automatic fallback selects one idle Hosted AP adapter");
Assert(SharingSession.SelectHostedOutput(new[]{idleWifi.Id},new[]{idleWifi with{Connected=true}})=="","Automatic fallback refuses a connected incoming Wi-Fi adapter");
Assert(HostedHotspot.CanResetOutput(idleWifi),"Unavailable AP recovery permits an idle Wi-Fi output");
Assert(!HostedHotspot.CanResetOutput(idleWifi with{Connected=true}),"AP recovery refuses a connected Wi-Fi input even without a default gateway");
Assert(HostedHotspot.CanResetOutput(idleWifi with{Gateways=new[]{"192.168.1.1"}}),"A disconnected Hosted AP card may retain an inactive DHCP gateway without becoming an incoming adapter");
Assert(!HostedHotspot.CanResetOutput(idleWifi with{Kind="VPN"})&&!HostedHotspot.CanResetOutput(idleWifi with{Kind="USB tethering"}),"AP recovery refuses VPN and USB input devices");
Assert(HostedHotspot.ShouldRetryStart(0x80342002,19,1,0),"Hosted AP retries the observed transient Wi-Fi power-state failure");
Assert(HostedHotspot.ShouldRetryStart(0x80342002,19,1,14),"Hosted AP keeps the bounded wake-up retry window open for fifteen seconds");
Assert(!HostedHotspot.ShouldRetryStart(0x80342002,19,1,15),"Hosted AP power-state retries stop at the bounded attempt limit");
Assert(!HostedHotspot.ShouldRetryStart(0x80342002,19,0,0)&&!HostedHotspot.ShouldRetryStart(0x80342001,19,1,0),"Hosted AP never retries unavailable or unrelated driver failures as a power transition");
var workGate=new OperationWorker();
var workEntered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var workRelease=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var firstWork=workGate.TryRunAsync(async()=>{workEntered.SetResult();await workRelease.Task;});
Assert(workEntered.Task.Wait(TimeSpan.FromSeconds(3))&&!firstWork.IsCompleted,"Slow lifecycle work returns control to the caller before completion");
bool duplicateRan=false;
Assert(!await workGate.TryRunAsync(()=>{duplicateRan=true;return Task.CompletedTask;})&&!duplicateRan,"Repeated clicks cannot queue overlapping lifecycle work");
workRelease.SetResult();Assert(await firstWork,"Original lifecycle work completes normally");
bool workerError=false;
try{await workGate.TryRunAsync(()=>throw new IOException("simulated failure"));}catch(IOException){workerError=true;}
Assert(workerError&&await workGate.TryRunAsync(()=>Task.CompletedTask),"Lifecycle failure releases the gate for a later retry");
var callerContext=new SynchronizationContext();SynchronizationContext.SetSynchronizationContext(callerContext);
bool workerHasUiContext=true;
await workGate.TryRunAsync(()=>{workerHasUiContext=SynchronizationContext.Current!=null;return Task.CompletedTask;});
SynchronizationContext.SetSynchronizationContext(null);
Assert(!workerHasUiContext,"Lifecycle worker does not inherit the caller UI synchronization context");
int uiHeartbeats=0;Exception? uiTestError=null;
var uiThread=new Thread(()=>{
    try{
        using var form=new System.Windows.Forms.Form{ShowInTaskbar=false,StartPosition=System.Windows.Forms.FormStartPosition.Manual,Location=new System.Drawing.Point(-30000,-30000)};
        using var heartbeat=new System.Windows.Forms.Timer{Interval=40};heartbeat.Tick+=(_,_)=>uiHeartbeats++;
        form.Shown+=async(_,_)=>{
            heartbeat.Start();
            try{await new OperationWorker().TryRunAsync(()=>{Thread.Sleep(400);return Task.CompletedTask;});}
            catch(Exception e){uiTestError=e;}
            finally{heartbeat.Stop();form.Close();}
        };
        System.Windows.Forms.Application.Run(form);
    }catch(Exception e){uiTestError=e;}
});
uiThread.SetApartmentState(ApartmentState.STA);uiThread.IsBackground=true;uiThread.Start();
Assert(uiThread.Join(TimeSpan.FromSeconds(8))&&uiTestError==null&&uiHeartbeats>=2,"Real WinForms message pump remains responsive during blocking lifecycle work");
byte[] Tcp(uint src,uint dst,ushort sp,ushort dp,uint seq,uint ackNo,byte flags,byte[]? payload=null){
    int n=payload?.Length??0;var packet=new byte[40+n];
    packet[0]=0x45;Packets.Put16(packet,2,(ushort)packet.Length);packet[8]=64;packet[9]=6;
    Packets.Put32(packet,12,src);Packets.Put32(packet,16,dst);Packets.Put16(packet,20,sp);Packets.Put16(packet,22,dp);
    Packets.Put32(packet,24,seq);Packets.Put32(packet,28,ackNo);packet[32]=0x50;packet[33]=flags;Packets.Put16(packet,34,65535);
    if(payload!=null)payload.CopyTo(packet,40);Packets.FixChecksums(packet,20,packet.Length);return packet;
}
bool WireOk(byte[] packet){
    int header=(packet[0]&15)*4,total=Packets.U16(packet,2);
    if(header<20||total!=packet.Length||Packets.Checksum(packet.AsSpan(0,header))!=0)return false;
    uint pseudo=(uint)(Packets.U16(packet,12)+Packets.U16(packet,14)+Packets.U16(packet,16)+Packets.U16(packet,18)+packet[9]+(total-header));
    return Packets.Checksum(packet.AsSpan(header,total-header),pseudo)==0;
}
var relayFactory=new FakeChannels();
var relayReplies=new List<byte[]>();
long relayNow=5_000;bool relayOpen=false;
var relay=new SocketRelay(Packets.Ip(gateway),vpnIp,15,()=>relayOpen,relayReplies.Add,relayFactory,()=>relayNow);
relay.Feed(Tcp(clientIp,remoteIp,40000,443,1000,0,0x02));
Assert(relayFactory.Opened.Count==0&&relay.Flows==0,"Socket relay drops client traffic while the VPN gate is closed");
relayOpen=true;
relay.Feed(Tcp(clientIp,Packets.Ip(IPAddress.Parse("127.0.0.1")),40000,443,1000,0,0x02));
relay.Feed(Tcp(clientIp,Packets.Ip(gateway)+30,40000,80,1000,0,0x02));
Assert(relayFactory.Opened.Count==0,"Socket relay does not follow loopback or the hotspot subnet");
var privateVpn=Packets.Ip(IPAddress.Parse("10.1.2.3"));
relay.Feed(Tcp(clientIp,privateVpn,40000,443,1000,0,0x02));
Assert(relayFactory.Opened.Count==1&&relayFactory.Opened[0].Protocol==6&&relayFactory.Opened[0].Remote==privateVpn&&relayFactory.Opened[0].Port==443,"Socket relay forces a private VPN destination through the selected tunnel");
var syn=relayReplies[^1];
Assert(syn[32]==0x60&&syn[33]==0x12&&Packets.U16(syn,42)==1200&&WireOk(syn),"Shared TCP answers the phone with a checksummed SYN-ACK and a VPN-safe MSS");
uint relayIsn=Packets.U32(syn,24);
var held=new FakeChannels{AutoReady=false};
var heldReplies=new List<byte[]>();
var heldRelay=new SocketRelay(Packets.Ip(gateway),vpnIp,15,()=>true,heldReplies.Add,held,()=>relayNow);
heldRelay.Feed(Tcp(clientIp,remoteIp,41000,443,1000,0,0x02));
uint heldIsn=Packets.U32(heldReplies[0],24);
heldRelay.Feed(Tcp(clientIp,remoteIp,41000,443,1001,heldIsn+1,0x18,new byte[]{1,2}));
Assert(held.Opened[0].Sent.Count==0&&heldRelay.Uploaded==2,"Client payload waits until the VPN socket is connected");
held.Opened[0].BecomeReady();
Assert(held.Opened[0].Sent.Count==1&&held.Opened[0].Sent[0].SequenceEqual(new byte[]{1,2}),"Queued client payload is flushed into the VPN socket");
relay.Feed(Tcp(clientIp,privateVpn,40000,443,1001,relayIsn+1,0x18,new byte[]{4,5,6,7}));
Assert(relayFactory.Opened[0].Sent.Single().SequenceEqual(new byte[]{4,5,6,7})&&relay.Uploaded==4,"Shared TCP payload is sent to the VPN unmodified");
relayFactory.Opened[0].Deliver(new byte[]{8,9});
var data=relayReplies.Last(packet=>packet[9]==6&&packet.Length>40&&(packet[33]&8)!=0);
Assert(Packets.U32(data,12)==privateVpn&&Packets.U32(data,16)==clientIp&&Packets.U32(data,24)==relayIsn+1&&Packets.U32(data,28)==1005&&data.AsSpan(40).SequenceEqual(new byte[]{8,9})&&WireOk(data)&&relay.Downloaded==2,"VPN responses are rewritten back to the phone with valid checksums");
relay.Feed(Tcp(clientIp,privateVpn,40000,443,1005,relayIsn+1+2,0x10));
int afterAck=relayReplies.Count;
relayNow+=5_000;relay.Tick();
Assert(relayReplies.Count==afterAck,"Acked VPN data is not retransmitted to the phone");
var retryFactory=new FakeChannels();
var retryReplies=new List<byte[]>();
long retryNow=1_000;
var retry=new SocketRelay(Packets.Ip(gateway),vpnIp,15,()=>true,retryReplies.Add,retryFactory,()=>retryNow);
retry.Feed(Tcp(clientIp,remoteIp,42000,443,50,0,0x02));
uint retryIsn=Packets.U32(retryReplies[0],24);
retryNow=2_000;retry.Tick();
Assert(retryReplies.Count==2&&Packets.U32(retryReplies[1],24)==retryIsn&&retryReplies[1][33]==0x12,"Unacknowledged shared handshakes are retransmitted");
retryFactory.Opened[0].Fail(new IOException("blocked"));
Assert(retry.Flows==0&&retryFactory.Opened[0].Disposed&&(retryReplies[^1][33]&4)!=0&&WireOk(retryReplies[^1]),"A VPN socket failure resets the phone flow instead of leaving it open");
var udpFactory=new FakeChannels();
var udpReplies=new List<byte[]>();
var udpRelay=new SocketRelay(Packets.Ip(gateway),vpnIp,15,()=>true,udpReplies.Add,udpFactory,()=>relayNow);
udpRelay.Feed(Datagram(clientIp,remoteIp,43000,53,32));
Assert(udpFactory.Opened.Count==1&&udpFactory.Opened[0].Protocol==17&&udpFactory.Opened[0].Port==53&&udpFactory.Opened[0].Sent.Count==1&&udpFactory.Opened[0].Sent[0].Length==4,"Shared UDP opens one VPN socket per client flow");
udpFactory.Opened[0].Deliver(new byte[]{9,8,7});
var udpReply=udpReplies.Single(packet=>packet[9]==17);
Assert(Packets.U32(udpReply,12)==remoteIp&&Packets.U32(udpReply,16)==clientIp&&Packets.U16(udpReply,20)==53&&Packets.U16(udpReply,22)==43000&&udpReply.AsSpan(28).SequenceEqual(new byte[]{9,8,7})&&WireOk(udpReply),"Shared UDP replies keep the phone's port and a valid checksum");

IPAddress? hostIp=null; int hostIf=0;
foreach(var nic in NetworkInterface.GetAllNetworkInterfaces()){
    if(nic.OperationalStatus!=OperationalStatus.Up||nic.NetworkInterfaceType==NetworkInterfaceType.Loopback)continue;
    var props=nic.GetIPProperties();
    var addr=props.UnicastAddresses.FirstOrDefault(a=>a.Address.AddressFamily==AddressFamily.InterNetwork&&!IPAddress.IsLoopback(a.Address)&&(Packets.Ip(a.Address)&0xffffff00)!=(Packets.Ip(gateway)&0xffffff00));
    if(addr==null)continue;
    hostIp=addr.Address; hostIf=props.GetIPv4Properties().Index; break;
}
Assert(hostIp!=null&&hostIf>0,"Real socket test found a local IPv4 interface");
var liveListener=new TcpListener(hostIp!,0);
liveListener.Start();
int livePort=((IPEndPoint)liveListener.LocalEndpoint!).Port;
var pendingAccept=liveListener.AcceptTcpClientAsync();
var liveReplies=new List<byte[]>();
using var liveRelay=new SocketRelay(Packets.Ip(gateway),Packets.Ip(hostIp!),hostIf,()=>true,liveReplies.Add);
liveRelay.Feed(Tcp(clientIp,Packets.Ip(hostIp!),45000,(ushort)livePort,1000,0,0x02));
Assert(liveReplies.Count>0&&liveReplies[0][33]==0x12,"Real Windows socket path answers the phone handshake");
uint liveIsn=Packets.U32(liveReplies[0],24);
var liveBody=System.Text.Encoding.ASCII.GetBytes("phone-ok");
liveRelay.Feed(Tcp(clientIp,Packets.Ip(hostIp!),45000,(ushort)livePort,1001,liveIsn+1,0x18,liveBody));
Assert(pendingAccept.Wait(TimeSpan.FromSeconds(8)),"Real VPN socket connected through the Windows interface");
using var liveServer=pendingAccept.Result;
var liveGot=new byte[liveBody.Length];
Assert(liveServer.GetStream().ReadExactlyAsync(liveGot).Wait(TimeSpan.FromSeconds(4))&&liveGot.SequenceEqual(liveBody),"Real VPN socket received the phone payload unchanged");
liveServer.GetStream().Write(new byte[]{9,9,9}); liveServer.GetStream().Flush();
var liveUntil=DateTime.UtcNow.AddSeconds(4); byte[] liveData=Array.Empty<byte>();
while(liveData.Length==0&&DateTime.UtcNow<liveUntil){liveData=liveReplies.LastOrDefault(p=>p.Length>40&&p[9]==6&&(p[33]&8)!=0)??Array.Empty<byte>(); if(liveData.Length==0)Thread.Sleep(30);}
Assert(liveData.Length>=43&&liveData.AsSpan(40,3).SequenceEqual(new byte[]{9,9,9})&&WireOk(liveData),"Real VPN response is translated back to the phone");
liveListener.Stop();

Console.WriteLine($"\n{passed} checks passed. No network configuration was changed.");


sealed class FakeChannels : SocketRelay.IChannels
{
    public bool AutoReady=true;
    public List<FakeChannel> Opened=new();
    public FakeChannels(){}
    public FakeChannels(bool autoReady){AutoReady=autoReady;}
    public SocketRelay.IChannel Open(byte protocol){var channel=new FakeChannel(protocol,AutoReady);Opened.Add(channel);return channel;}
}
sealed class FakeChannel : SocketRelay.IChannel
{
    public byte Protocol; public uint Remote; public ushort Port; public bool Disposed;
    public List<byte[]> Sent=new();
    readonly bool autoReady;
    Action? ready;
    Action<byte[]>? received;
    Action<Exception>? failed;
    public FakeChannel(byte protocol,bool autoReady){Protocol=protocol;this.autoReady=autoReady;}
    public void Start(uint remote,ushort port,Action onReady,Action<byte[]> onData,Action onClose,Action<Exception> onFail)
    {Remote=remote;Port=port;ready=onReady;received=onData;failed=onFail;if(autoReady)onReady();}
    public bool Send(byte[] data){Sent.Add(data);return true;}
    public void ShutdownSend(){}
    public void Dispose()=>Disposed=true;
    public void BecomeReady()=>ready?.Invoke();
    public void Deliver(byte[] data)=>received?.Invoke(data);
    public void Fail(Exception error)=>failed?.Invoke(error);
}
sealed class FakePacketEngine(bool connected) : IPacketEngine
{
    public bool Connected=>connected;
    public bool Faulted{get;set;}
    public bool Disposed{get;private set;}
    public bool FailDispose{get;set;}
    public long Uploaded=>0;
    public long Downloaded=>0;
    public long Dropped=>0;
    public int Flows=>0;
    public event Action<string>? Message {add{}remove{}}
    public event Action<Exception>? Fault {add{}remove{}}
    public void Start(){}
    public void Dispose(){Disposed=true;if(FailDispose)throw new IOException("simulated cleanup failure");}
}
