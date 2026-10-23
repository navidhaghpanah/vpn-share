using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace VpnShare;

public sealed class NdisNatProtocol : IDisposable
{
    readonly uint vpn,gateway,subnet;
    readonly int mtu;
    readonly NatTable table;
    readonly Func<uint,bool> route;
    public int Flows=>table.Count;
    public NdisNatProtocol(uint vpnIp,uint gatewayIp,int tunnelMtu,Func<byte,ushort,Socket?> reserve,Func<uint,bool> routesThroughVpn)
    {vpn=vpnIp;gateway=gatewayIp;subnet=gateway&0xffffff00;mtu=Math.Clamp(tunnelMtu,576,1280);table=new(reserve);route=routesThroughVpn;}
    public bool Outbound(byte[] packet,bool connected,out byte[]? tooBig)
    {
        tooBig=null;
        if(!connected||!Packets.Parse(packet,packet.Length,out int header,out int total)||packet[8]<=1)return false;
        byte protocol=packet[9];uint client=Packets.U32(packet,12),remote=Packets.U32(packet,16);
        if((client&0xffffff00)!=subnet||client<=gateway||client>=subnet+255||!Unicast(remote)||(remote&0xffffff00)==subnet||!route(remote))return false;
        ushort clientPort,remotePort;
        if(protocol is 6 or 17){clientPort=Packets.U16(packet,header);remotePort=Packets.U16(packet,header+2);}
        else if(protocol==1&&packet[header]==8){clientPort=Packets.U16(packet,header+4);remotePort=0;}
        else return false;
        if(total>mtu){
            int quoted=Math.Min(total,header+8);tooBig=new byte[28+quoted];tooBig[0]=0x45;Packets.Put16(tooBig,2,(ushort)tooBig.Length);tooBig[8]=64;tooBig[9]=1;
            Packets.Put32(tooBig,12,gateway);Packets.Put32(tooBig,16,client);tooBig[20]=3;tooBig[21]=4;Packets.Put16(tooBig,26,(ushort)mtu);Array.Copy(packet,0,tooBig,28,quoted);Packets.FixChecksums(tooBig,20,tooBig.Length);return false;
        }
        var flow=table.GetOrCreate(new(protocol,client,clientPort,remote,remotePort));if(flow==null)return false;
        Packets.Put32(packet,12,vpn);Packets.Put16(packet,header+(protocol==1?4:0),flow.Port);packet[8]--;
        Packets.ClampMss(packet,header,total,(ushort)(mtu-40));Packets.FixChecksums(packet,header,total);return true;
    }
    // 0: unrelated host traffic; 1: translated; -1: belongs to NAT but blocked.
    public int Inbound(byte[] packet,bool connected)
    {
        if(!Packets.Parse(packet,packet.Length,out int header,out int total)||Packets.U32(packet,16)!=vpn)return 0;
        byte protocol=packet[9];ushort port,remotePort;
        if(protocol is 6 or 17){port=Packets.U16(packet,header+2);remotePort=Packets.U16(packet,header);}
        else if(protocol==1&&packet[header]==0){port=Packets.U16(packet,header+4);remotePort=0;}
        else return 0;
        var flow=table.Find(protocol,port,Packets.U32(packet,12),remotePort);if(flow==null)return 0;
        if(!connected||packet[8]<=1)return -1;
        Packets.Put32(packet,16,flow.Key.Client);Packets.Put16(packet,header+(protocol==1?4:2),flow.Key.ClientPort);packet[8]--;
        Packets.ClampMss(packet,header,total,(ushort)(mtu-40));Packets.FixChecksums(packet,header,total);return 1;
    }
    static bool Unicast(uint ip)=>ip>>24 is >0 and <224&&ip>>24!=127&&(ip&0xffff0000)!=0xa9fe0000;
    public void Expire()=>table.Expire(Environment.TickCount64);
    public void Clear()=>table.Dispose();
    public void Dispose()=>table.Dispose();
}

public sealed class NdisNatEngine : IPacketEngine
{
    readonly NdisDevice device;
    readonly NdisAdapter down,up;
    readonly byte[] upLocal,upRemote;
    readonly NdisNatProtocol protocol;
    readonly DhcpProtocol dhcp;
    readonly AdapterInfo source;
    readonly SessionState session;
    readonly uint gateway,vpn;
    readonly Dictionary<uint,byte[]> clients=new();
    readonly CancellationTokenSource cancel=new();
    readonly object ioGate=new();
    Task? worker,monitor;
    bool modesSet;
    volatile bool connected,faulted;
    long uploaded,downloaded,dropped;
    public bool Connected=>connected;
    public bool Faulted=>faulted;
    public long Uploaded=>Interlocked.Read(ref uploaded);
    public long Downloaded=>Interlocked.Read(ref downloaded);
    public long Dropped=>Interlocked.Read(ref dropped);
    public int Flows=>protocol.Flows;
    public event Action<string>? Message;
    public event Action<Exception>? Fault;
    public NdisNatEngine(AdapterInfo vpnAdapter,SessionState state,DhcpProtocol? addressing=null)
    {
        dhcp=addressing??new DhcpProtocol(IPAddress.Parse(state.Gateway),IPAddress.Parse(state.Gateway));
        source=vpnAdapter;session=state;gateway=Packets.Ip(IPAddress.Parse(state.Gateway));vpn=Packets.Ip(AdapterCatalog.VpnAddress(source));device=new();
        try{
            var adapters=device.Adapters();
            down=Find(adapters,state.AdapterId)??throw new InvalidOperationException("The output interface is not exposed by Windows Packet Filter. This Wi-Fi/LAN driver is unsupported.");
            up=Find(adapters,source.Id)!;
            if(up!=null){
                upLocal=up.Mac;
                if(up.Medium==19){
                    // WinpkFilter presents NdisMediumIP packets with a synthetic
                    // Ethernet header. The layer-3 tunnel has no ARP next hop.
                    upLocal=new byte[6];upRemote=new byte[6];
                }else{
                var next=source.Gateways.Select(IPAddress.Parse).FirstOrDefault()??IPAddress.Parse("1.1.1.1");
                var bytes=new byte[6];int size=6;
                if(SendARP(BitConverter.ToUInt32(next.GetAddressBytes()),BitConverter.ToUInt32(AdapterCatalog.VpnAddress(source).GetAddressBytes()),bytes,ref size)!=0||size!=6)
                    throw new InvalidOperationException("The VPN next-hop Ethernet address could not be resolved. Use a supported Ethernet VPN or native IKEv2 tunnel.");
                upRemote=bytes;
                }
            }else{
                var matches=new List<(NdisAdapter Adapter,NdisWanLink Link)>();
                foreach(var adapter in adapters.Where(a=>NdisDevice.IsWanIpv4(a.Name)))
                    foreach(var link in device.WanLinks(adapter))if(link.Address.SequenceEqual(AdapterCatalog.VpnAddress(source).GetAddressBytes()))matches.Add((adapter,link));
                if(matches.Count!=1)throw new InvalidOperationException("The selected VPN has no unique driver-visible IPv4 WAN link. Its packet interface is unsupported or still connecting.");
                up=matches[0].Adapter;upLocal=matches[0].Link.Local;upRemote=matches[0].Link.Remote;
            }
            if(up.Handle==down.Handle)throw new InvalidOperationException("VPN and output cannot be the same driver interface.");
            if(device.GetMode(up)!=0||device.GetMode(down)!=0)throw new InvalidOperationException("Another packet filter owns a selected interface. Stop that filter before sharing.");
            protocol=new(vpn,gateway,Math.Min(source.Mtu,1280),(kind,port)=>{
                if(kind==1)return null;var socket=new Socket(AddressFamily.InterNetwork,kind==6?SocketType.Stream:SocketType.Dgram,kind==6?ProtocolType.Tcp:ProtocolType.Udp);
                try{socket.ExclusiveAddressUse=true;socket.Bind(new IPEndPoint(Packets.Address(vpn),port));return socket;}catch{socket.Dispose();throw;}
            },remote=>Routes.UsesInterface(Packets.Address(remote),source.Index));
        }catch{device.Dispose();throw;}
    }
    static NdisAdapter? Find(NdisAdapter[] adapters,string id)=>adapters.SingleOrDefault(a=>a.Name.Contains(id.Trim('{','}'),StringComparison.OrdinalIgnoreCase));
    public void Start()
    {
        try{
            // RECEIVE tunnel only: host sends are never queued. Unknown receives
            // are returned to TCP/IP; client internet is consumed before routing.
            session.NdisInterfaces=new(){down.Name,up.Name};NetworkSetup.Save(session);
            modesSet=true;device.SetMode(down,2);device.SetMode(up,2);connected=CheckVpn();
            Message?.Invoke(up.Medium==19?"IP tunnel backend active. No Ethernet ARP is used for this VPN.":"Ethernet/WAN tunnel backend active.");
            worker=Task.Run(Loop);monitor=Task.Run(Monitor);
        }catch{connected=false;ResetModes();throw;}
    }
    bool CheckVpn(){var current=AdapterCatalog.Read().FirstOrDefault(a=>a.Id==source.Id);return current is{Connected:true}&&current.Index==source.Index&&current.IPv4.Contains(Packets.Address(vpn).ToString())&&Routes.UsesInterface(IPAddress.Parse("1.1.1.1"),source.Index);}
    async Task Monitor()
    {
        try{while(!cancel.IsCancellationRequested){lock(ioGate){if(device.GetMode(down)!=2||device.GetMode(up)!=2)throw new InvalidOperationException("A packet interface filter mode changed unexpectedly.");}bool active=!faulted&&CheckVpn();if(active!=connected){connected=active;protocol.Clear();Message?.Invoke(active?"VPN restored.":"VPN unavailable; client internet is blocked.");}protocol.Expire();await Task.Delay(500,cancel.Token);}}
        catch(OperationCanceledException){}catch(Exception e){Fail(e);}
    }
    void Fail(Exception e){connected=false;faulted=true;Fault?.Invoke(e);}
    void Loop()
    {
        var buffer=new byte[NdisDevice.BufferHeader+NdisDevice.FrameCapacity];
        try{while(!cancel.IsCancellationRequested){bool any=false;lock(ioGate){foreach(var adapter in new[]{down,up})for(int batch=0;batch<128&&!cancel.IsCancellationRequested;batch++){
            if(!device.Read(adapter,buffer))break;any=true;Handle(adapter,buffer);
        }}if(!any)cancel.Token.WaitHandle.WaitOne(2);}}
        catch(Exception e){if(!cancel.IsCancellationRequested)Fail(e);}
    }
    void Handle(NdisAdapter adapter,byte[] buffer)
    {
        uint length=BitConverter.ToUInt32(buffer,20);bool receive=(BitConverter.ToUInt32(buffer,16)&2)!=0;
        if(length<14||length>NdisDevice.FrameCapacity){Interlocked.Increment(ref dropped);return;}
        if(!receive){device.Send(adapter,buffer,false);return;}
        var frame=buffer.AsSpan(NdisDevice.BufferHeader,(int)length);
        if(frame[12]!=8||frame[13]!=0){device.Send(adapter,buffer,true);return;}
        var ip=frame[14..].ToArray();
        if(adapter.Handle==down.Handle){
            if(NdisDhcp.Handle(dhcp,ip,frame.Slice(6,6),gateway,out var offer)){
                if(offer!=null)device.SendFrame(down,Frame(offer,down.Mac,new byte[]{255,255,255,255,255,255}));return;
            }
            // Keep gateway DHCP/DNS/ARP and link-local broadcasts on the host.
            // All off-link IPv4 goes through NAT, never through host forwarding.
            if(ip.Length>=20){uint client=Packets.U32(ip,12),remote=Packets.U32(ip,16);
                if(remote==gateway||remote==0xffffffff||(remote&0xffffff00)==(gateway&0xffffff00)){device.Send(adapter,buffer,true);return;}
                if((client&0xffffff00)==(gateway&0xffffff00)&&client>gateway&&client<(gateway|255))clients[client]=frame.Slice(6,6).ToArray();
            }
            if(protocol.Outbound(ip,connected,out var tooBig)){device.SendFrame(up,Frame(ip,upLocal,upRemote));Interlocked.Add(ref uploaded,ip.Length);}
            else{Interlocked.Increment(ref dropped);if(tooBig!=null&&clients.TryGetValue(Packets.U32(tooBig,16),out var mac))device.SendFrame(down,Frame(tooBig,down.Mac,mac));}
        }else{
            int result=protocol.Inbound(ip,connected);
            if(result==0){device.Send(adapter,buffer,true);return;}
            if(result<0||!clients.TryGetValue(Packets.U32(ip,16),out var mac)){Interlocked.Increment(ref dropped);return;}
            device.SendFrame(down,Frame(ip,down.Mac,mac));Interlocked.Add(ref downloaded,ip.Length);
        }
    }
    public static byte[] Frame(byte[] packet,byte[] local,byte[] remote){if(local.Length!=6||remote.Length!=6)throw new ArgumentException("Ethernet address must contain six bytes.");var frame=new byte[14+packet.Length];remote.CopyTo(frame,0);local.CopyTo(frame,6);frame[12]=8;packet.CopyTo(frame,14);return frame;}
    void ResetModes(){if(!modesSet)return;Exception? error=null;foreach(var adapter in new[]{up,down})try{device.SetMode(adapter,0);session.NdisInterfaces.Remove(adapter.Name);NetworkSetup.Save(session);}catch(Exception e){error=e;}if(error!=null)throw new InvalidOperationException("Packet adapter mode restoration failed.",error);modesSet=false;}
    public void Dispose()
    {
        connected=false;cancel.Cancel();Task.WaitAll(new[]{worker,monitor}.Where(t=>t!=null).Cast<Task>().ToArray(),TimeSpan.FromSeconds(5));
        try{lock(ioGate)ResetModes();}finally{device.Dispose();protocol.Dispose();cancel.Dispose();}
    }
    [DllImport("iphlpapi.dll")]static extern uint SendARP(uint destination,uint source,byte[] mac,ref int length);
}

public static class NdisRecovery
{
    public static void Restore(SessionState session)
    {
        if(session.NdisInterfaces.Count==0)return;
        using var device=new NdisDevice();var adapters=device.Adapters();
        foreach(var name in session.NdisInterfaces.ToArray()){
            var adapter=adapters.SingleOrDefault(a=>a.Name==name);
            if(adapter!=null){uint mode=device.GetMode(adapter);if(mode!=0&&mode!=2)throw new InvalidOperationException("A journaled interface now has an unrelated filter mode. Recovery retained the protection rules.");if(mode==2)device.SetMode(adapter,0);}
            session.NdisInterfaces.Remove(name);NetworkSetup.Save(session);
        }
    }
}
