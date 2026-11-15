using System.Net;
using System.Net.Sockets;

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
    readonly NdisAdapter down;
    readonly SocketRelay relay;
    readonly DhcpProtocol dhcp;
    readonly AdapterInfo source;
    readonly SessionState session;
    readonly uint gateway,vpn;
    readonly Dictionary<uint,byte[]> clients=new();
    readonly CancellationTokenSource cancel=new();
    readonly object ioGate=new();
    readonly byte[] broadcast=new byte[]{255,255,255,255,255,255};
    Task? worker,monitor;
    bool modesSet;
    int failureReported,disposed,statusTick;
    volatile bool connected,faulted;
    long dropped;
    public bool Connected=>connected;
    public bool Faulted=>faulted;
    public long Uploaded=>relay.Uploaded;
    public long Downloaded=>relay.Downloaded;
    public long Dropped=>Interlocked.Read(ref dropped)+relay.Dropped;
    public int Flows=>relay.Flows;
    public event Action<string>? Message;
    public event Action<Exception>? Fault;
    public NdisNatEngine(AdapterInfo vpnAdapter,SessionState state,DhcpProtocol? addressing=null)
    {
        dhcp=addressing??new DhcpProtocol(IPAddress.Parse(state.Gateway),IPAddress.Parse(state.Gateway));
        source=vpnAdapter;session=state;gateway=Packets.Ip(IPAddress.Parse(state.Gateway));vpn=Packets.Ip(AdapterCatalog.VpnAddress(source));device=new();
        SocketRelay? made=null;
        try{
            var adapters=device.Adapters();
            down=Find(adapters,state.AdapterId)??throw new InvalidOperationException("The output interface is not exposed by Windows Packet Filter. This Wi-Fi/LAN driver is unsupported.");
            if(device.GetMode(down)!=0)throw new InvalidOperationException("Another packet filter owns the shared interface. Stop that filter before sharing.");
            made=new SocketRelay(gateway,vpn,source.Index,()=>connected,EmitToClient,notify:text=>Message?.Invoke(text));
            relay=made;
        }catch{made?.Dispose();device.Dispose();throw;}
    }
    static NdisAdapter? Find(NdisAdapter[] adapters,string id)=>adapters.SingleOrDefault(a=>a.Name.Contains(id.Trim('{','}'),StringComparison.OrdinalIgnoreCase));
    public void Start()
    {
        try{
            if(session.NdisInterfaces.Count!=0)throw new InvalidOperationException("Previous packet bindings still need recovery before restarting.");
            session.NdisInterfaces=new(){down.Name};session.NdisHandles=new(){{down.Name,down.Handle}};NetworkSetup.Save(session);
            modesSet=true;device.SetMode(down,2);connected=CheckVpn();
            worker=Task.Run(Loop);monitor=Task.Run(Monitor);
            Message?.Invoke(connected
                ? "Any connected VPN is shared through Windows. WireGuard, IKEv2, OpenVPN, VLESS and Windscribe use the same path."
                : "The selected VPN is not up; client internet stays blocked.");
        }catch{connected=false;ResetModes();throw;}
    }
    bool CheckVpn()
    {
        var current=AdapterCatalog.Read().FirstOrDefault(a=>a.Id==source.Id);
        return current is{Connected:true}&&current.Index==source.Index&&current.IPv4.Contains(Packets.Address(vpn).ToString());
    }
    async Task Monitor()
    {
        try{while(!cancel.IsCancellationRequested){
            lock(ioGate){if(device.GetMode(down)!=2)throw new InvalidOperationException("The shared interface filter changed unexpectedly.");}
            bool active=!faulted&&CheckVpn();
            if(active!=connected){connected=active;if(!active)relay.Suspend();Message?.Invoke(active?"VPN restored.":"VPN unavailable; client internet is blocked.");}
            if(++statusTick%20==0)Message?.Invoke($"Share: {(connected?"VPN up":"VPN down")}, flows {Flows}, up {Uploaded}, down {Downloaded}, dropped {Dropped}.");
            relay.Tick();await Task.Delay(500,cancel.Token);
        }}
        catch(OperationCanceledException){}catch(Exception e){Fail(e);}
    }
    void Fail(Exception e){connected=false;faulted=true;cancel.Cancel();if(Interlocked.Exchange(ref failureReported,1)==0)Fault?.Invoke(e);}
    void Loop()
    {
        var buffer=new byte[NdisDevice.BufferHeader+NdisDevice.FrameCapacity];
        var batch=new List<byte[]>();
        try{while(!cancel.IsCancellationRequested){
            batch.Clear();bool any=false;
            lock(ioGate){for(int n=0;n<128&&!cancel.IsCancellationRequested;n++){
                if(!device.Read(down,buffer))break;any=true;batch.Add((byte[])buffer.Clone());
            }}
            foreach(var item in batch)Deliver(item);
            if(!any)cancel.Token.WaitHandle.WaitOne(2);
        }}
        catch(Exception e){if(!cancel.IsCancellationRequested)Fail(e);}
    }
    void Deliver(byte[] buffer)
    {
        uint length=BitConverter.ToUInt32(buffer,20);bool receive=(BitConverter.ToUInt32(buffer,16)&2)!=0;
        if(length<14||length>NdisDevice.FrameCapacity){Interlocked.Increment(ref dropped);return;}
        if(!receive){lock(ioGate)device.Send(down,buffer,false);return;}
        var frame=buffer.AsSpan(NdisDevice.BufferHeader,(int)length);
        if(frame[12]!=8||frame[13]!=0){lock(ioGate)device.Send(down,buffer,true);return;}
        var ip=frame.Slice(14).ToArray();
        if(NdisDhcp.Handle(dhcp,ip,frame.Slice(6,6),gateway,out var offer)){
            if(offer!=null)lock(ioGate)device.SendFrame(down,Frame(offer,down.Mac,broadcast));
            return;
        }
        if(ip.Length>=20){
            uint client=Packets.U32(ip,12),remote=Packets.U32(ip,16);
            if((client&0xffffff00)==(gateway&0xffffff00)&&client>gateway&&client<(gateway|255))lock(ioGate)clients[client]=frame.Slice(6,6).ToArray();
            if(remote==gateway||remote==0xffffffff||(remote&0xffffff00)==(gateway&0xffffff00)){lock(ioGate)device.Send(down,buffer,true);return;}
        }
        relay.Feed(ip);
    }
    void EmitToClient(byte[] ip)
    {
        if(Volatile.Read(ref disposed)!=0||ip.Length<20)return;
        uint client=Packets.U32(ip,16);
        lock(ioGate){
            if(Volatile.Read(ref disposed)!=0||!clients.TryGetValue(client,out var mac))return;
            device.SendFrame(down,Frame(ip,down.Mac,mac));
        }
    }
    public static byte[] Frame(byte[] packet,byte[] local,byte[] remote){if(local.Length!=6||remote.Length!=6)throw new ArgumentException("Ethernet address must contain six bytes.");var frame=new byte[14+packet.Length];remote.CopyTo(frame,0);local.CopyTo(frame,6);frame[12]=8;packet.CopyTo(frame,14);return frame;}
    void ResetModes(){if(!modesSet)return;try{NdisRecovery.Restore(session,device.Adapters(),device.GetMode,device.SetMode,()=>NetworkSetup.Save(session));modesSet=false;}catch(Exception e){throw new InvalidOperationException("Packet adapter mode restoration failed; the journal was retained for retry.",e);}}
    public void Dispose()
    {
        if(Interlocked.Exchange(ref disposed,1)!=0)return;
        connected=false;cancel.Cancel();Task.WaitAll(new[]{worker,monitor}.Where(t=>t!=null).Cast<Task>().ToArray(),TimeSpan.FromSeconds(5));
        try{relay.Dispose();lock(ioGate)ResetModes();}finally{device.Dispose();cancel.Dispose();}
    }
}
public static class NdisRecovery
{
    public static void Restore(SessionState session)
    {
        if(session.NdisInterfaces.Count==0)return;
        using var device=new NdisDevice();Restore(session,device.Adapters(),device.GetMode,device.SetMode,()=>NetworkSetup.Save(session));
    }
    public static void Restore(SessionState session,NdisAdapter[] adapters,Func<NdisAdapter,uint> getMode,Action<NdisAdapter,uint> setMode,Action persist)
    {
        Exception? error=null;
        foreach(var name in session.NdisInterfaces.ToArray()){
            try{
                var adapter=adapters.SingleOrDefault(a=>a.Name.Equals(name,StringComparison.OrdinalIgnoreCase));
                bool replaced=adapter!=null&&session.NdisHandles.TryGetValue(name,out var owned)&&owned!=adapter.Handle;
                if(adapter!=null&&!replaced){uint mode=getMode(adapter);if(mode!=0&&mode!=2)throw new InvalidOperationException("A journaled interface now has an unrelated filter mode. Recovery retained the protection rules.");if(mode==2)setMode(adapter,0);}
                session.NdisInterfaces.Remove(name);session.NdisHandles.Remove(name);persist();
            }catch(Exception e){error=e;}
        }
        if(error!=null)throw new InvalidOperationException("One or more packet bindings still need recovery.",error);
    }
}
