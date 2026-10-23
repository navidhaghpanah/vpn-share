namespace VpnShare;

public static class NdisDhcp
{
    // Consume client DHCP before the Windows stack, avoiding a second OS DHCP
    // responder or a port-67 ownership conflict on autonomous Wi-Fi Direct APs.
    public static bool Handle(DhcpProtocol protocol,byte[] packet,ReadOnlySpan<byte> mac,uint gateway,out byte[]? reply)
    {
        reply=null;
        if(!Packets.Parse(packet,packet.Length,out int header,out int total)||packet[9]!=17||Packets.U16(packet,header)!=68||Packets.U16(packet,header+2)!=67)return false;
        var request=packet.AsSpan(header+8,total-header-8);
        if(mac.Length!=6||request.Length<240||!request.Slice(28,6).SequenceEqual(mac))return true;
        var payload=protocol.Reply(request.ToArray());if(payload==null)return true;
        reply=new byte[28+payload.Length];reply[0]=0x45;reply[8]=64;reply[9]=17;Packets.Put16(reply,2,(ushort)reply.Length);
        Packets.Put32(reply,12,gateway);Packets.Put32(reply,16,uint.MaxValue);Packets.Put16(reply,20,67);Packets.Put16(reply,22,68);Packets.Put16(reply,24,(ushort)(8+payload.Length));payload.CopyTo(reply,28);Packets.FixChecksums(reply,20,reply.Length);return true;
    }
}
