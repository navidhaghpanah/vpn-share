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

Console.WriteLine($"\n{passed} checks passed. No network configuration was changed.");

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
