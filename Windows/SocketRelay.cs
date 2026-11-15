using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace VpnShare;

// Phone packets are captured on the hotspot NIC, then re-created as ordinary
// Windows sockets bound to the VPN address. Any connected VPN works, because
// this is the same path the PC itself uses. Traffic is not injected into the
// tunnel driver, so WireGuard, IKEv2, OpenVPN, VLESS and Windscribe share one path.
public sealed class SocketRelay : IDisposable
{
    public interface IChannel : IDisposable
    {
        void Start(uint remote, ushort port, Action ready, Action<byte[]> received, Action closed, Action<Exception> failed);
        bool Send(byte[] data);
        void ShutdownSend();
    }
    public interface IChannels
    {
        IChannel Open(byte protocol);
    }

    const int Mss=1200;
    readonly uint gateway,subnet;
    readonly Func<bool> connected;
    readonly Action<byte[]> emit;
    readonly Action<string>? notify;
    readonly IChannels channels;
    readonly Func<long> clock;
    readonly object sync=new();
    readonly Dictionary<FlowKey,TcpFlow> tcp=new();
    readonly Dictionary<FlowKey,UdpFlow> udp=new();
    int disposed,notes,ipId;
    long uploaded,downloaded,dropped;

    public long Uploaded=>Interlocked.Read(ref uploaded);
    public long Downloaded=>Interlocked.Read(ref downloaded);
    public long Dropped=>Interlocked.Read(ref dropped);
    public int Flows{get{lock(sync)return tcp.Count+udp.Count;}}

    public SocketRelay(uint gateway,uint vpn,int interfaceIndex,Func<bool> connected,Action<byte[]> emit,IChannels? channels=null,Func<long>? clock=null,Action<string>? notify=null)
    {
        this.gateway=gateway;subnet=gateway&0xffffff00;this.connected=connected;this.emit=emit;this.notify=notify;
        this.channels=channels??new HostChannels(vpn,interfaceIndex);this.clock=clock??(()=>Environment.TickCount64);
    }

    public void Feed(byte[] ip)
    {
        if(Volatile.Read(ref disposed)!=0||!connected())return;
        if(!Packets.Parse(ip,ip.Length,out int header,out int total)){Interlocked.Increment(ref dropped);return;}
        uint client=Packets.U32(ip,12),remote=Packets.U32(ip,16);
        if(!IsClient(client)||!IsForeign(remote))return;
        if(ip[9]==6)FeedTcp(ip,header,total,client,remote);
        else if(ip[9]==17)FeedUdp(ip,header,total,client,remote);
    }

    public void Tick()
    {
        if(Volatile.Read(ref disposed)!=0)return;
        long now=clock();
        lock(sync){
            foreach(var flow in tcp.Values.ToArray()){
                if(flow.Dead)continue;
                if(now-flow.LastSeen>180_000){Kill(flow,true);continue;}
                if(now-flow.LastXmit>=1000)Retransmit(flow);
            }
            foreach(var flow in udp.Values.ToArray()){
                if(!flow.Dead&&now-flow.LastSeen>120_000)Kill(flow);
            }
        }
    }

    public void Suspend()
    {
        lock(sync){
            foreach(var flow in tcp.Values.ToArray())Kill(flow,true);
            foreach(var flow in udp.Values.ToArray())Kill(flow);
        }
    }

    public void Dispose()
    {
        if(Interlocked.Exchange(ref disposed,1)!=0)return;
        lock(sync){
            foreach(var flow in tcp.Values){flow.Dead=true;try{flow.Channel.Dispose();}catch{}}
            foreach(var flow in udp.Values){flow.Dead=true;try{flow.Channel.Dispose();}catch{}}
            tcp.Clear();udp.Clear();
        }
    }

    bool IsClient(uint ip)=>(ip&0xffffff00)==subnet&&ip>gateway&&ip<(subnet+255);
    bool IsForeign(uint ip)
    {
        if((ip&0xffffff00)==subnet)return false;
        uint a=ip>>24;
        if(a==0||a>=224||a==127)return false;
        return (ip&0xffff0000)!=0xa9fe0000;
    }

    void FeedTcp(byte[] ip,int header,int total,uint client,uint remote)
    {
        int tcpLen=(ip[header+12]>>4)*4;
        if(tcpLen<20||header+tcpLen>total){Interlocked.Increment(ref dropped);return;}
        ushort sport=Packets.U16(ip,header),dport=Packets.U16(ip,header+2);
        uint seq=Packets.U32(ip,header+4),ack=Packets.U32(ip,header+8);
        byte flags=ip[header+13];ushort window=Packets.U16(ip,header+14);
        int at=header+tcpLen,len=total-at;
        var key=new FlowKey(6,client,sport,remote,dport);
        TcpFlow? created=null;
        lock(sync){
            if(tcp.TryGetValue(key,out var flow)){
                flow.LastSeen=clock();
                flow.PeerWindow=window;
                if((flags&4)!=0){Kill(flow,false);return;}
                if((flags&2)!=0&&(flags&16)==0){if(!flow.SynAcked)ResendSyn(flow);return;}
                Accept(flow,seq,ack,flags,ip,at,len);
                return;
            }
            if((flags&2)==0||(flags&16)!=0||(flags&4)!=0||tcp.Count+udp.Count>=400)return;
            var channel=channels.Open(6);
            var opened=new TcpFlow{Id=key,Channel=channel,Isn=(uint)Random.Shared.Next(1,int.MaxValue),RcvNxt=seq+1,PeerWindow=window==0?1:window,LastSeen=clock()};
            tcp[key]=opened;created=opened;ResendSyn(opened);
        }
        if(created!=null)ArmTcp(created);
    }

    void ArmTcp(TcpFlow flow)
    {
        try{flow.Channel.Start(flow.Id.Remote,flow.Id.RemotePort,()=>OnReady(flow),data=>OnData(flow,data),()=>OnClosed(flow),e=>Fail(flow,e));}
        catch(Exception e){Fail(flow,e);}
    }

    void Accept(TcpFlow flow,uint seq,uint ack,byte flags,byte[] ip,int at,int len)
    {
        if(flow.Dead)return;
        NoteAck(flow,ack);
        if(len>0){
            if(seq==flow.RcvNxt){
                var chunk=ip.AsSpan(at,len).ToArray();
                bool took=false;
                if(!flow.Ready){
                    if(flow.EarlyBytes+chunk.Length<=128*1024){flow.Early.Add(chunk);flow.EarlyBytes+=chunk.Length;took=true;}
                }else took=flow.Channel.Send(chunk);
                if(took){flow.RcvNxt+=(uint)chunk.Length;Interlocked.Add(ref uploaded,chunk.Length);}
            }
        }
        if((flags&1)!=0&&!flow.ClientFin&&seq+(uint)len==flow.RcvNxt){
            flow.ClientFin=true;flow.RcvNxt++;
            try{flow.Channel.ShutdownSend();}catch{}
        }
        if((flags&16)!=0||len>0||(flags&1)!=0)EmitAck(flow);
        Pump(flow);
        if(flow.FinAcked&&flow.ClientFin)Kill(flow,false);
    }

    void NoteAck(TcpFlow flow,uint ack)
    {
        uint start=flow.Isn+1;
        int rel=unchecked((int)(ack-start));
        if(rel<0)return;
        uint off=(uint)rel;
        uint sentEnd=(uint)flow.AckedTotal+(uint)flow.Inflight;
        if(off>sentEnd+1)return;
        bool finAck=false;
        if(off==sentEnd+1){
            if(!(flow.FinSent&&flow.Inflight==flow.Buf.Count))return;
            finAck=true;off=sentEnd;
        }
        if(off<(uint)flow.AckedTotal)return;
        int newly=(int)(off-(uint)flow.AckedTotal);
        if(newly>0){flow.Buf.RemoveRange(0,newly);flow.Inflight-=newly;flow.AckedTotal+=newly;}
        flow.SynAcked=true;
        if(finAck)flow.FinAcked=true;
    }

    void OnReady(TcpFlow flow)
    {
        lock(sync){
            if(flow.Dead||Volatile.Read(ref disposed)!=0)return;
            flow.Ready=true;
            while(flow.Early.Count>0){
                if(!flow.Channel.Send(flow.Early[0]))return;
                flow.EarlyBytes-=flow.Early[0].Length;flow.Early.RemoveAt(0);
            }
        }
    }

    void OnData(TcpFlow flow,byte[] data)
    {
        if(data.Length==0)return;
        while(true){
            lock(sync){
                if(flow.Dead||flow.HostClosed||Volatile.Read(ref disposed)!=0)return;
                if(flow.Buf.Count<256*1024){flow.Buf.AddRange(data);flow.LastSeen=clock();Pump(flow);return;}
            }
            Thread.Sleep(20);
        }
    }

    void OnClosed(TcpFlow flow)
    {
        lock(sync){
            if(flow.Dead||Volatile.Read(ref disposed)!=0)return;
            flow.HostClosed=true;flow.LastSeen=clock();Pump(flow);
            if(flow.FinAcked&&flow.ClientFin)Kill(flow,false);
        }
    }

    void Fail(TcpFlow flow,Exception error)
    {
        lock(sync){
            if(flow.Dead||Volatile.Read(ref disposed)!=0)return;
            Notify(error);Kill(flow,true);
        }
    }

    void Pump(TcpFlow flow)
    {
        int guard=0;
        while(flow.Inflight<flow.Buf.Count&&guard++<32){
            int room=flow.PeerWindow-flow.Inflight;
            if(room<=0)break;
            int n=Math.Min(Mss,Math.Min(room,flow.Buf.Count-flow.Inflight));
            if(n<=0)break;
            Emit(Segment(flow,flow.Isn+1+(uint)flow.AckedTotal+(uint)flow.Inflight,0x18,flow.Buf.GetRange(flow.Inflight,n).ToArray(),false));
            flow.Inflight+=n;flow.LastXmit=clock();Interlocked.Add(ref downloaded,n);
        }
        if(flow.HostClosed&&!flow.FinSent&&flow.Inflight==flow.Buf.Count){
            Emit(Segment(flow,flow.Isn+1+(uint)flow.AckedTotal+(uint)flow.Buf.Count,0x11,Array.Empty<byte>(),false));
            flow.FinSent=true;flow.LastXmit=clock();
        }
    }

    void Retransmit(TcpFlow flow)
    {
        if(!flow.SynAcked){ResendSyn(flow);return;}
        if(flow.Inflight>0){
            int n=Math.Min(Mss,flow.Inflight);
            Emit(Segment(flow,flow.Isn+1+(uint)flow.AckedTotal,0x18,flow.Buf.GetRange(0,n).ToArray(),false));
            flow.LastXmit=clock();return;
        }
        if(flow.FinSent&&!flow.FinAcked){
            Emit(Segment(flow,flow.Isn+1+(uint)flow.AckedTotal+(uint)flow.Buf.Count,0x11,Array.Empty<byte>(),false));
            flow.LastXmit=clock();
        }
    }

    void ResendSyn(TcpFlow flow)
    {
        Emit(Segment(flow,flow.Isn,0x12,Array.Empty<byte>(),true));
        flow.LastXmit=clock();
    }

    void EmitAck(TcpFlow flow)=>Emit(Segment(flow,flow.Isn+1+(uint)flow.AckedTotal+(uint)flow.Inflight,0x10,Array.Empty<byte>(),false));

    void FeedUdp(byte[] ip,int header,int total,uint client,uint remote)
    {
        int len=total-header-8;if(len<=0)return;
        ushort sport=Packets.U16(ip,header),dport=Packets.U16(ip,header+2);
        var key=new FlowKey(17,client,sport,remote,dport);
        var payload=ip.AsSpan(header+8,len).ToArray();
        UdpFlow? created=null;
        lock(sync){
            UdpFlow flow;
            if(udp.TryGetValue(key,out var found))flow=found;
            else{
                if(udp.Count+tcp.Count>=400)return;
                flow=new UdpFlow{Id=key,Channel=channels.Open(17),LastSeen=clock()};
                udp[key]=flow;created=flow;
            }
            flow.LastSeen=clock();
            if(flow.Ready){if(flow.Channel.Send(payload))Interlocked.Add(ref uploaded,payload.Length);}
            else if(flow.Early.Count<128)flow.Early.Enqueue(payload);
        }
        if(created!=null)ArmUdp(created);
    }

    void ArmUdp(UdpFlow flow)
    {
        try{flow.Channel.Start(flow.Id.Remote,flow.Id.RemotePort,()=>OnUdpReady(flow),data=>OnUdp(flow,data),()=>{},e=>Fail(flow,e));}
        catch(Exception e){Fail(flow,e);}
    }

    void OnUdpReady(UdpFlow flow)
    {
        lock(sync){
            if(flow.Dead||Volatile.Read(ref disposed)!=0)return;
            flow.Ready=true;
            while(flow.Early.Count>0){
                var chunk=flow.Early.Peek();
                if(!flow.Channel.Send(chunk))return;
                flow.Early.Dequeue();Interlocked.Add(ref uploaded,chunk.Length);
            }
        }
    }

    void OnUdp(UdpFlow flow,byte[] data)
    {
        lock(sync){
            if(flow.Dead||Volatile.Read(ref disposed)!=0||data.Length==0)return;
            flow.LastSeen=clock();
            Emit(Datagram(flow.Id.Remote,flow.Id.Client,flow.Id.RemotePort,flow.Id.ClientPort,data));
            Interlocked.Add(ref downloaded,data.Length);
        }
    }

    void Fail(UdpFlow flow,Exception error)
    {
        lock(sync){
            if(flow.Dead||Volatile.Read(ref disposed)!=0)return;
            Notify(error);Kill(flow);
        }
    }

    void Kill(TcpFlow flow,bool reset)
    {
        if(flow.Dead)return;
        flow.Dead=true;tcp.Remove(flow.Id);
        if(reset&&Volatile.Read(ref disposed)==0)Emit(Segment(flow,flow.Isn+1+(uint)flow.AckedTotal+(uint)flow.Inflight,0x14,Array.Empty<byte>(),false));
        try{flow.Channel.Dispose();}catch{}
    }

    void Kill(UdpFlow flow)
    {
        if(flow.Dead)return;
        flow.Dead=true;udp.Remove(flow.Id);
        try{flow.Channel.Dispose();}catch{}
    }

    void Notify(Exception error)
    {
        if(notes>=3)return;notes++;
        var text=error is AggregateException aggregate&&aggregate.InnerException!=null?aggregate.InnerException.Message:error.Message;
        notify?.Invoke("Shared traffic could not enter the VPN: "+text);
    }

    void Emit(byte[] packet){if(Volatile.Read(ref disposed)==0)emit(packet);}

    byte[] Segment(TcpFlow flow,uint seq,byte flags,byte[] payload,bool mss)
    {
        int option=mss?4:0,tcp=20+option;
        var packet=new byte[20+tcp+payload.Length];
        packet[0]=0x45;Packets.Put16(packet,2,(ushort)packet.Length);Packets.Put16(packet,4,NextId());Packets.Put16(packet,6,0x4000);
        packet[8]=64;packet[9]=6;Packets.Put32(packet,12,flow.Id.Remote);Packets.Put32(packet,16,flow.Id.Client);
        Packets.Put16(packet,20,flow.Id.RemotePort);Packets.Put16(packet,22,flow.Id.ClientPort);
        Packets.Put32(packet,24,seq);Packets.Put32(packet,28,flow.RcvNxt);
        packet[32]=(byte)((tcp/4)<<4);packet[33]=flags;Packets.Put16(packet,34,65535);
        if(mss){packet[40]=2;packet[41]=4;Packets.Put16(packet,42,Mss);}
        payload.CopyTo(packet,20+tcp);Packets.FixChecksums(packet,20,packet.Length);return packet;
    }

    byte[] Datagram(uint src,uint dst,ushort sport,ushort dport,byte[] payload)
    {
        var packet=new byte[28+payload.Length];
        packet[0]=0x45;Packets.Put16(packet,2,(ushort)packet.Length);Packets.Put16(packet,4,NextId());
        packet[8]=64;packet[9]=17;Packets.Put32(packet,12,src);Packets.Put32(packet,16,dst);
        Packets.Put16(packet,20,sport);Packets.Put16(packet,22,dport);Packets.Put16(packet,24,(ushort)(8+payload.Length));
        payload.CopyTo(packet,28);Packets.FixChecksums(packet,20,packet.Length);return packet;
    }

    ushort NextId()=>(ushort)Interlocked.Increment(ref ipId);

    readonly record struct FlowKey(byte Protocol,uint Client,ushort ClientPort,uint Remote,ushort RemotePort);
    sealed class TcpFlow
    {
        public FlowKey Id;
        public IChannel Channel=null!;
        public uint Isn,RcvNxt;
        public int PeerWindow=65535,Inflight,AckedTotal,EarlyBytes;
        public bool SynAcked,Ready,ClientFin,HostClosed,FinSent,FinAcked,Dead;
        public long LastSeen,LastXmit;
        public List<byte> Buf=new();
        public List<byte[]> Early=new();
    }
    sealed class UdpFlow
    {
        public FlowKey Id;
        public IChannel Channel=null!;
        public bool Ready,Dead;
        public long LastSeen;
        public Queue<byte[]> Early=new();
    }

    sealed class HostChannels(uint vpn,int iface) : IChannels
    {
        public IChannel Open(byte protocol)=>new HostChannel(protocol,vpn,iface);
    }

    sealed class HostChannel : IChannel
    {
        readonly byte protocol;
        readonly uint vpn;
        readonly int iface;
        readonly ConcurrentQueue<byte[]> outbound=new();
        readonly SemaphoreSlim wake=new(0);
        Socket? socket;
        int dead,shut;
        public HostChannel(byte protocol,uint vpn,int iface){this.protocol=protocol;this.vpn=vpn;this.iface=iface;}
        public bool Send(byte[] data)
        {
            if(Volatile.Read(ref dead)!=0||outbound.Count>=128)return false;
            outbound.Enqueue(data);wake.Release();return true;
        }
        public void ShutdownSend()
        {
            Interlocked.Exchange(ref shut,1);
            try{socket?.Shutdown(SocketShutdown.Send);}catch{}
        }
        public void Start(uint remote,ushort port,Action ready,Action<byte[]> received,Action closed,Action<Exception> failed)
        {
            Task.Run(()=>{
                try{
                    var stream=protocol==6;
                    var current=new Socket(AddressFamily.InterNetwork,stream?SocketType.Stream:SocketType.Dgram,stream?ProtocolType.Tcp:ProtocolType.Udp);
                    socket=current;
                    current.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(iface));
                    current.Bind(new IPEndPoint(Packets.Address(vpn),0));
                    if(stream)current.NoDelay=true;
                    var endpoint=new IPEndPoint(Packets.Address(remote),port);
                    if(stream){
                        var task=current.ConnectAsync(endpoint);
                        if(!task.Wait(8000))throw new TimeoutException("The VPN did not answer the shared connection.");
                    }else current.Connect(endpoint);
                    if(Volatile.Read(ref shut)==1){try{current.Shutdown(SocketShutdown.Send);}catch{}}
                    ready();
                    var reading=Task.Run(()=>{
                        var buffer=new byte[65535];
                        try{
                            while(Volatile.Read(ref dead)==0){
                                int size=current.Receive(buffer);
                                if(size==0){closed();return;}
                                var copy=new byte[size];Buffer.BlockCopy(buffer,0,copy,0,size);received(copy);
                            }
                        }catch(Exception error){if(Volatile.Read(ref dead)==0)failed(error);}
                    });
                    while(Volatile.Read(ref dead)==0){
                        wake.Wait(250);
                        while(outbound.TryDequeue(out var chunk)){
                            int offset=0;
                            while(offset<chunk.Length){
                                int sent=current.Send(chunk,offset,chunk.Length-offset,SocketFlags.None);
                                if(sent<=0)throw new IOException("VPN socket closed.");
                                offset+=sent;
                            }
                        }
                    }
                    reading.Wait(100);
                }catch(Exception error){if(Volatile.Read(ref dead)==0&&Volatile.Read(ref shut)==0)failed(error);}
            });
        }
        public void Dispose()
        {
            if(Interlocked.Exchange(ref dead,1)!=0)return;
            try{socket?.Dispose();}catch{}
            wake.Release();
        }
    }
}
