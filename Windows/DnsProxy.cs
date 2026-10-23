using System.Net;
using System.Net.Sockets;

namespace VpnShare;

public sealed record DnsUpstream(IPAddress Source,int Interface,IPAddress Resolver,int Port=53);
public static class DnsWire
{
    public static bool IsQuery(ReadOnlySpan<byte> packet)
    {
        if(packet.Length is <12 or >65535 || (packet[2]&0xf8)!=0 || packet[4]!=0 || packet[5] is 0 or >16)return false;
        int offset=12;
        for(int question=0;question<packet[5];question++){
            int position=offset,next=-1,total=0,jumps=0;
            while(true){
                if(position>=packet.Length||++jumps>128)return false;
                int length=packet[position++];
                if(length==0){offset=next<0?position:next;break;}
                if((length&0xc0)==0xc0){
                    if(position>=packet.Length)return false;
                    if(next<0)next=position+1;
                    position=((length&63)<<8)|packet[position];if(position<12)return false;continue;
                }
                if(length>63||position+length>packet.Length||(total+=length+1)>255)return false;
                position+=length;
            }
            if(offset+4>packet.Length)return false;offset+=4;
        }
        return true;
    }
    public static bool Matches(ReadOnlySpan<byte> query,ReadOnlySpan<byte> answer)=>answer.Length>=12 && query.Length>=12 && query[0]==answer[0] && query[1]==answer[1] && (answer[2]&0x80)!=0;
}

public sealed class DnsProxy : IDisposable
{
    readonly Socket udp;
    readonly TcpListener tcp;
    readonly CancellationTokenSource cancellation=new();
    readonly SemaphoreSlim budget=new(64);
    readonly Func<bool> allowed;
    readonly uint subnet;
    DnsUpstream upstream;
    readonly System.Collections.Concurrent.ConcurrentDictionary<Task,byte> active=new();
    Task? udpWorker,tcpWorker;
    public event Action<Exception>? Fault;
    public int Port=>((IPEndPoint)udp.LocalEndPoint!).Port;
    public DnsProxy(IPAddress gateway,DnsUpstream target,Func<bool> connected,int listenPort=53)
    {
        subnet=Packets.Ip(gateway)&0xffffff00;upstream=target;allowed=connected;
        udp=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
        try{udp.ExclusiveAddressUse=true;udp.Bind(new IPEndPoint(gateway,listenPort));}catch{udp.Dispose();throw;}
        tcp=new TcpListener(gateway,Port);
        try{tcp.Start(32);}catch{udp.Dispose();tcp.Stop();throw;}
    }
    public void Update(DnsUpstream target)=>Volatile.Write(ref upstream,target);
    bool ClientAllowed(EndPoint? endpoint)=>allowed()&&endpoint is IPEndPoint ip&&ip.Address.AddressFamily==AddressFamily.InterNetwork&&(Packets.Ip(ip.Address)&0xffffff00)==subnet;
    Socket Upstream(ProtocolType protocol,DnsUpstream target)
    {
        var socket=new Socket(AddressFamily.InterNetwork,protocol==ProtocolType.Tcp?SocketType.Stream:SocketType.Dgram,protocol);
        try{socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(target.Interface));socket.Bind(new IPEndPoint(target.Source,0));return socket;}catch{socket.Dispose();throw;}
    }
    public void Start()
    {
        udpWorker=Task.Run(async()=>{
            var buffer=new byte[65535];
            try{while(!cancellation.IsCancellationRequested){
                var result=await udp.ReceiveFromAsync(buffer,SocketFlags.None,new IPEndPoint(IPAddress.Any,0),cancellation.Token);
                if(!ClientAllowed(result.RemoteEndPoint)||!DnsWire.IsQuery(buffer.AsSpan(0,result.ReceivedBytes))||!budget.Wait(0))continue;
                var query=buffer.AsSpan(0,result.ReceivedBytes).ToArray();var remote=result.RemoteEndPoint;
                Track(Task.Run(async()=>{using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);timeout.CancelAfter(TimeSpan.FromSeconds(6));
                    try{
                        var target=Volatile.Read(ref upstream);using var outbound=Upstream(ProtocolType.Udp,target);
                        await outbound.ConnectAsync(new IPEndPoint(target.Resolver,target.Port),timeout.Token);await outbound.SendAsync(query,SocketFlags.None,timeout.Token);
                        var reply=new byte[65535];int size=await outbound.ReceiveAsync(reply,SocketFlags.None,timeout.Token);
                        if(allowed()&&ReferenceEquals(target,Volatile.Read(ref upstream))&&DnsWire.Matches(query,reply.AsSpan(0,size)))await udp.SendToAsync(reply.AsMemory(0,size),SocketFlags.None,remote,timeout.Token);
                    }catch(Exception e)when(e is SocketException or OperationCanceledException or ObjectDisposedException){}finally{budget.Release();}
                }));
            }}catch(Exception e)when(cancellation.IsCancellationRequested&&e is OperationCanceledException or SocketException or ObjectDisposedException){}
            catch(Exception e){Fault?.Invoke(e);}
        });
        tcpWorker=Task.Run(async()=>{
            try{while(!cancellation.IsCancellationRequested){
                var client=await tcp.AcceptTcpClientAsync(cancellation.Token);
                if(!ClientAllowed(client.Client.RemoteEndPoint)||!budget.Wait(0)){client.Dispose();continue;}
                Track(Task.Run(async()=>{using(client)using(var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token)){
                    timeout.CancelAfter(TimeSpan.FromSeconds(12));
                    try{
                        var input=client.GetStream();var length=new byte[2];await input.ReadExactlyAsync(length,timeout.Token);int count=length[0]*256+length[1];
                        if(count<12)return;var query=new byte[count];await input.ReadExactlyAsync(query,timeout.Token);if(!DnsWire.IsQuery(query))return;
                        var target=Volatile.Read(ref upstream);using var outbound=Upstream(ProtocolType.Tcp,target);await outbound.ConnectAsync(new IPEndPoint(target.Resolver,target.Port),timeout.Token);
                        using var stream=new NetworkStream(outbound,false);await stream.WriteAsync(length,timeout.Token);await stream.WriteAsync(query,timeout.Token);
                        await stream.ReadExactlyAsync(length,timeout.Token);count=length[0]*256+length[1];if(count<12)return;var reply=new byte[count];await stream.ReadExactlyAsync(reply,timeout.Token);
                        if(allowed()&&ReferenceEquals(target,Volatile.Read(ref upstream))&&DnsWire.Matches(query,reply)){await input.WriteAsync(length,timeout.Token);await input.WriteAsync(reply,timeout.Token);}
                    }catch(Exception e)when(e is SocketException or IOException or OperationCanceledException or ObjectDisposedException){}finally{budget.Release();}
                }}));
            }}catch(Exception e)when(cancellation.IsCancellationRequested&&e is OperationCanceledException or SocketException or ObjectDisposedException){}
            catch(Exception e){Fault?.Invoke(e);}
        });
    }
    void Track(Task task){active.TryAdd(task,0);_=task.ContinueWith(completed=>active.TryRemove(completed,out _),TaskScheduler.Default);}
    public void Dispose()
    {
        cancellation.Cancel();udp.Dispose();tcp.Stop();
        var tasks=active.Keys.Concat(new[]{udpWorker,tcpWorker}.Where(x=>x!=null).Cast<Task>()).ToArray();
        Task.WaitAll(tasks,TimeSpan.FromSeconds(3));
        // Pending socket operations observe cancellation; no network fallback exists.
    }
}
