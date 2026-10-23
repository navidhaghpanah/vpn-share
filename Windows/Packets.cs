using System.Buffers.Binary;
using System.Net;

namespace VpnShare;

public static class Packets
{
    public static ushort U16(byte[] b, int p) => BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(p, 2));
    public static uint U32(byte[] b, int p) => BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(p, 4));
    public static void Put16(byte[] b, int p, ushort n) => BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(p, 2), n);
    public static void Put32(byte[] b, int p, uint n) => BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(p, 4), n);
    public static uint Ip(IPAddress a) => BinaryPrimitives.ReadUInt32BigEndian(a.GetAddressBytes());
    public static IPAddress Address(uint a) { var b = new byte[4]; Put32(b,0,a); return new IPAddress(b); }

    public static bool Parse(byte[] b, int length, out int header, out int total)
    {
        header=0; total=0;
        if (length < 20 || b[0] >> 4 != 4) return false;
        header=(b[0]&15)*4; total=U16(b,2);
        if (header < 20 || total > length || total < header || (U16(b,6)&0x3fff)!=0) return false;
        if (b[9]==6) return total >= header+20 && (b[header+12]>>4)*4 >= 20 && header+(b[header+12]>>4)*4 <= total;
        if (b[9]==17) return total >= header+8 && U16(b,header+4)>=8 && U16(b,header+4)==total-header;
        return b[9]==1 && total>=header+8;
    }
    public static ushort Checksum(ReadOnlySpan<byte> data, uint seed=0)
    {
        uint sum=seed;
        for(int i=0;i<data.Length;i+=2) sum+=(uint)(data[i]<<8 | (i+1<data.Length ? data[i+1] : 0));
        while((sum>>16)!=0) sum=(sum&65535)+(sum>>16);
        return (ushort)~sum;
    }
    public static void FixChecksums(byte[] b,int header,int total)
    {
        Put16(b,10,0); Put16(b,10,Checksum(b.AsSpan(0,header)));
        var protocol=b[9];
        if (protocol==1) { Put16(b,header+2,0); Put16(b,header+2,Checksum(b.AsSpan(header,total-header))); return; }
        int offset=header+(protocol==6?16:6);
        Put16(b,offset,0);
        uint sum=(uint)(U16(b,12)+U16(b,14)+U16(b,16)+U16(b,18)+protocol+total-header);
        ushort checksum=Checksum(b.AsSpan(header,total-header),sum);
        Put16(b,offset,checksum==0 && protocol==17 ? (ushort)65535 : checksum);
    }
    public static void ClampMss(byte[] b,int header,int total,ushort maximum)
    {
        if(b[9]!=6 || (b[header+13]&2)==0) return;
        int end=header+(b[header+12]>>4)*4;
        for(int p=header+20;p<end;) {
            int kind=b[p]; if(kind==0) break; if(kind==1) {p++; continue;}
            if(p+1>=end || b[p+1]<2 || p+b[p+1]>end) break;
            if(kind==2 && b[p+1]==4 && U16(b,p+2)>maximum) Put16(b,p+2,maximum);
            p+=b[p+1];
        }
    }
}
