using System.Net;

namespace VpnShare;

public sealed record SubnetRoute(string DestinationPrefix,string NextHop);

public static class SubnetSelector
{
    public static string ChooseRoutes(IEnumerable<SubnetRoute> routes)=>Choose(routes
        .Where(route=>!IsForwardedPrivateSummary(route)).Select(route=>route.DestinationPrefix));
    static bool IsForwardedPrivateSummary(SubnetRoute route)=>
        route.DestinationPrefix is "10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16"
        &&IPAddress.TryParse(route.NextHop,out var next)&&next.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork
        &&!next.Equals(IPAddress.Any);
    public static string Choose(IEnumerable<string> prefixes)
    {
        var existing=new List<(uint Address,uint Mask)>();
        foreach(var prefix in prefixes){
            var pieces=prefix.Split('/');
            if(pieces.Length!=2||!int.TryParse(pieces[1],out int bits)||bits is <2 or >32||!IPAddress.TryParse(pieces[0],out var ip)||ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork)continue;
            existing.Add((Packets.Ip(ip),uint.MaxValue<<(32-Math.Min(bits,24))));
        }
        var choices=Enumerable.Range(203,47).Select(i=>$"10.{i}.91.1")
            .Concat(Enumerable.Range(200,50).Select(i=>$"172.29.{i}.1"))
            .Concat(Enumerable.Range(233,22).Select(i=>$"192.168.{i}.1"));
        foreach(var choice in choices){uint address=Packets.Ip(IPAddress.Parse(choice));if(!existing.Any(p=>(address&p.Mask)==(p.Address&p.Mask)))return choice;}
        throw new InvalidOperationException("No unused private subnet was found.");
    }
}
