using System.Net;

namespace VpnShare;

public static class SubnetSelector
{
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
