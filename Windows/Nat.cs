using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace VpnShare;

public readonly record struct FlowKey(byte Protocol,uint Client,ushort ClientPort,uint Remote,ushort RemotePort);
public sealed class NatFlow : IDisposable
{
    public required FlowKey Key {get;init;}
    public required ushort Port {get;init;}
    public Socket? Reservation {get;init;}
    public long Seen {get;set;}=Environment.TickCount64;
    public void Dispose()=>Reservation?.Dispose();
}

public sealed class NatTable : IDisposable
{
    readonly Dictionary<FlowKey,NatFlow> forward=new();
    readonly Dictionary<(byte,ushort),NatFlow> reverse=new();
    readonly Func<byte,ushort,Socket?> reserve;
    ushort next=40000;
    public NatTable(Func<byte,ushort,Socket?> reservation)=>reserve=reservation;
    public int Count {get{lock(forward)return forward.Count;}}
    public NatFlow? GetOrCreate(FlowKey key)
    {
        lock(forward) {
            if(forward.TryGetValue(key,out var existing)) {existing.Seen=Environment.TickCount64;return existing;}
            if(forward.Count>=8192)return null;
            for(int i=0;i<10000;i++) {
                ushort port=next++;if(next>=50000)next=40000;
                if(reverse.ContainsKey((key.Protocol,port)))continue;
                Socket? socket;
                try{socket=reserve(key.Protocol,port);}catch(SocketException){continue;}
                var flow=new NatFlow {Key=key,Port=port,Reservation=socket};
                forward[key]=flow;reverse[(key.Protocol,port)]=flow;return flow;
            }
            return null;
        }
    }
    public NatFlow? Find(byte protocol,ushort port,uint remote,ushort remotePort)
    {
        lock(forward) {
            if(!reverse.TryGetValue((protocol,port),out var flow) || flow.Key.Remote!=remote || flow.Key.RemotePort!=remotePort)return null;
            flow.Seen=Environment.TickCount64;return flow;
        }
    }
    public void Expire(long now)
    {
        lock(forward)foreach(var flow in forward.Values.Where(x=>now-x.Seen>(x.Key.Protocol==6?600000:120000)).ToArray()) {
            forward.Remove(flow.Key);reverse.Remove((flow.Key.Protocol,flow.Port));flow.Dispose();
        }
    }
    public void Dispose(){lock(forward){foreach(var f in forward.Values)f.Dispose();forward.Clear();reverse.Clear();}}
}

public static class Routes
{
    public static bool UsesInterface(IPAddress destination,int index)
    {
        var sockaddr=new byte[16];sockaddr[0]=2;destination.GetAddressBytes().CopyTo(sockaddr,4);
        return GetBestInterfaceEx(sockaddr,out uint best)==0 && best==(uint)index;
    }
    [DllImport("iphlpapi.dll")] static extern uint GetBestInterfaceEx(byte[] destination,out uint index);
}
