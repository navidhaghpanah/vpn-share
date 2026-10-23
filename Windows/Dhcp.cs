using System.Net;
using System.Net.Sockets;

namespace VpnShare;

public sealed class Lease
{
    public required string Mac {get;init;}
    public required string Address {get;init;}
    public DateTime Expires {get;set;}
    public string Hostname {get;set;}="";
}

public sealed class DhcpProtocol
{
    readonly uint gateway,dns,network;
    readonly Dictionary<string,Lease> leases=new();
    public DhcpProtocol(IPAddress address,IPAddress resolver) {gateway=Packets.Ip(address);dns=Packets.Ip(resolver);network=gateway&0xffffff00;}
    public Lease[] Leases {get { lock(leases) return leases.Values.Where(x=>x.Expires>DateTime.UtcNow).Select(x=>new Lease {Mac=x.Mac,Address=x.Address,Hostname=x.Hostname,Expires=x.Expires}).ToArray(); }}
    public byte[]? Reply(byte[] request)
    {
        if(request.Length<240 || request[0]!=1 || request[1]!=1 || request[2]!=6 || request[3]>0 ||
           Packets.U32(request,236)!=0x63825363 || Packets.U32(request,24)!=0) return null;
        var options=new Dictionary<byte,byte[]>();
        for(int p=240;p<request.Length;) {
            byte kind=request[p++]; if(kind==255) break; if(kind==0) continue;
            if(p>=request.Length) return null;
            int count=request[p++]; if(p+count>request.Length) return null;
            options[kind]=request.AsSpan(p,count).ToArray(); p+=count;
        }
        if(!options.TryGetValue(53,out var types) || types.Length!=1) return null;
        if(options.TryGetValue(54,out var server) && (server.Length!=4 || Packets.U32(server,0)!=gateway)) return null;
        byte type=types[0];
        string mac=Convert.ToHexString(request.AsSpan(28,6));
        lock(leases) {
            foreach(var expired in leases.Where(x=>x.Value.Expires<=DateTime.UtcNow).Select(x=>x.Key).ToArray()) leases.Remove(expired);
            if(type==7) {leases.Remove(mac);return null;}
            if(type!=1 && type!=3) return null;
            if(!leases.TryGetValue(mac,out var lease)) {
                var used=leases.Values.Select(x=>Packets.Ip(IPAddress.Parse(x.Address))).ToHashSet();
                uint chosen=Enumerable.Range(20,200).Select(x=>network+(uint)x).FirstOrDefault(x=>!used.Contains(x));
                if(chosen==0) return null;
                lease=new Lease {Mac=mac,Address=Packets.Address(chosen).ToString(),Expires=DateTime.UtcNow.AddMinutes(2)};
                leases[mac]=lease;
            }
            uint offered=Packets.Ip(IPAddress.Parse(lease.Address));
            uint requested=Packets.U32(request,12);
            if(options.TryGetValue(50,out var wanted) && wanted.Length==4) requested=Packets.U32(wanted,0);
            bool nak=type==3 && requested!=0 && requested!=offered;
            if(!nak) {
                lease.Expires=DateTime.UtcNow.AddSeconds(type==1?120:3600);
                if(options.TryGetValue(12,out var host)) lease.Hostname=new string(System.Text.Encoding.ASCII.GetString(host).Where(c=>c>=32 && c<127).Take(63).ToArray());
            }
            var reply=new byte[300];
            Array.Copy(request,reply,Math.Min(236,request.Length));
            reply[0]=2; reply[3]=0; reply[8]=reply[9]=0;
            Packets.Put16(reply,10,0x8000); Packets.Put32(reply,12,0);
            Packets.Put32(reply,16,nak?0:offered); Packets.Put32(reply,20,gateway); Packets.Put32(reply,24,0);
            Array.Clear(reply,44,192); Packets.Put32(reply,236,0x63825363);
            int cursor=240;
            void Option(byte key,params byte[] value) {reply[cursor++]=key;reply[cursor++]=(byte)value.Length;value.CopyTo(reply,cursor);cursor+=value.Length;}
            byte[] Ip(uint value) {var b=new byte[4];Packets.Put32(b,0,value);return b;}
            Option(53,nak?(byte)6:type==1?(byte)2:(byte)5);
            Option(54,Ip(gateway));
            if(!nak) {
                Option(1,255,255,255,0);Option(3,Ip(gateway));Option(6,Ip(dns));
                Option(51,0,0,14,16);Option(58,0,0,7,8);Option(59,0,0,12,78);
                Option(26,5,0);
            }
            reply[cursor]=255;
            return reply;
        }
    }
}

public sealed class DhcpServer : IDisposable
{
    readonly Socket socket;
    readonly CancellationTokenSource cancel=new();
    readonly int index;
    public DhcpProtocol Protocol {get;}
    public event Action<Exception>? Fault;
    Task? worker;
    public DhcpServer(int downstream,IPAddress gateway,IPAddress resolver)
    {
        index=downstream;Protocol=new(gateway,resolver);
        socket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
        try {
            socket.ExclusiveAddressUse=true;
            socket.SetSocketOption(SocketOptionLevel.IP,SocketOptionName.PacketInformation,true);
            socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(index)); // IP_UNICAST_IF
            socket.EnableBroadcast=true;
            socket.Bind(new IPEndPoint(IPAddress.Any,67));
        } catch {socket.Dispose();throw;}
    }
    public void Start()=>worker=Task.Run(async()=> {
        var buffer=new byte[1500];
        try {
            while(!cancel.IsCancellationRequested) {
                var result=await socket.ReceiveMessageFromAsync(buffer,SocketFlags.None,new IPEndPoint(IPAddress.Any,0),cancel.Token);
                if(result.PacketInformation.Interface!=index || ((IPEndPoint)result.RemoteEndPoint).Port!=68) continue;
                var reply=Protocol.Reply(buffer.AsSpan(0,result.ReceivedBytes).ToArray());
                if(reply!=null) await socket.SendToAsync(reply,SocketFlags.None,new IPEndPoint(IPAddress.Broadcast,68),cancel.Token);
            }
        } catch(Exception e) when(cancel.IsCancellationRequested && e is OperationCanceledException or ObjectDisposedException or SocketException) {}
        catch(Exception e) {Fault?.Invoke(e);}
    });
    public void Dispose() {cancel.Cancel();socket.Dispose();worker?.Wait(TimeSpan.FromSeconds(2));cancel.Dispose();}
}
