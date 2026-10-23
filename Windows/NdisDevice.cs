using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Microsoft.Win32;

namespace VpnShare;

public sealed record NdisAdapter(long Handle,string Name,byte[] Mac,ushort Mtu,uint Medium=0);
public sealed record NdisWanLink(byte[] Local,byte[] Remote,byte[] Address);

// Native x64 ABI from NT Kernel's published Common.h. No unsigned native DLL.
// The driver installer is licensed separately for personal use.
public sealed unsafe class NdisDevice : IDisposable
{
    readonly SafeFileHandle handle;
    public const int BufferHeader=52,FrameCapacity=1514,AdapterListBytes=8836;
    public static uint Code(int operation)=>0x83000000u|((uint)(0x830+operation)<<2);
    public NdisDevice()
    {
        if(IntPtr.Size!=8)throw new PlatformNotSupportedException("The packet backend requires x64.");
        handle=CreateFileW(@"\\.\NDISRD",0,3,IntPtr.Zero,3,0,IntPtr.Zero);
        if(handle.IsInvalid){int error=Marshal.GetLastWin32Error();handle.Dispose();throw new Win32Exception(error,"Windows Packet Filter is not installed or cannot be opened.");}
    }
    public static bool Available {get{try{using var device=new NdisDevice();return true;}catch{return false;}}}
    public static object Inspect()
    {
        try{using var device=new NdisDevice();return new{Available=true,Adapters=device.Adapters().Select(a=>new{Name=a.Name,Handle=a.Handle,Mtu=a.Mtu,Mac=Convert.ToHexString(a.Mac),Mode=device.GetMode(a),WanLinks=IsWanIpv4(a.Name)?device.WanLinks(a):Array.Empty<NdisWanLink>()}).ToArray(),Error=""};}
        catch(Exception e){return new{Available=false,Error=e.Message};}
    }
    public static bool IsWanIpv4(string name)
    {
        if(name.Equals(@"\DEVICE\NDISWANIP",StringComparison.OrdinalIgnoreCase))return true;
        using var network=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}");
        if(network==null)return false;
        foreach(var child in network.GetSubKeyNames()){
            if(child.Length!=4||!child.All(char.IsDigit))continue;
            try{
            using var key=network.OpenSubKey(child);
            if(key==null||!string.Equals(key.GetValue("ComponentId") as string,"ms_ndiswanip",StringComparison.OrdinalIgnoreCase))continue;
            using var linkage=key.OpenSubKey("Linkage");var exported=linkage?.GetValue("Export");
            if(exported is string[] names&&names.Any(n=>n.Equals(name,StringComparison.OrdinalIgnoreCase)))return true;
            if(exported is string text&&text.Equals(name,StringComparison.OrdinalIgnoreCase))return true;
            }catch(System.Security.SecurityException){}catch(UnauthorizedAccessException){}
        }
        return false;
    }
    bool Io(int op,void* input,int inputSize,void* output,int outputSize)=>DeviceIoControl(handle,Code(op),(IntPtr)input,(uint)inputSize,(IntPtr)output,(uint)outputSize,out _,IntPtr.Zero);
    void Check(bool success,string operation){if(!success)throw new Win32Exception(Marshal.GetLastWin32Error(),"Packet driver: "+operation);}
    public NdisAdapter[] Adapters()
    {
        var bytes=new byte[AdapterListBytes];
        fixed(byte* p=bytes)Check(Io(1,p,bytes.Length,p,bytes.Length),"enumerate interfaces");
        return ParseAdapters(bytes);
    }
    public static NdisAdapter[] ParseAdapters(byte[] bytes)
    {
        if(bytes.Length!=AdapterListBytes)throw new InvalidDataException("Invalid adapter list length.");
        uint count=BitConverter.ToUInt32(bytes,0);if(count>32)throw new InvalidDataException("Driver adapter list exceeds capacity.");
        var result=new List<NdisAdapter>();
        for(int i=0;i<count;i++){
            var name=Encoding.ASCII.GetString(bytes,4+256*i,256).Split('\0')[0];
            result.Add(new(BitConverter.ToInt64(bytes,8196+8*i),name,bytes.AsSpan(8580+6*i,6).ToArray(),BitConverter.ToUInt16(bytes,8772+2*i),BitConverter.ToUInt32(bytes,8452+4*i)));
        }
        return result.ToArray();
    }
    public NdisWanLink[] WanLinks(NdisAdapter adapter)
    {
        long id=adapter.Handle;var bytes=new byte[4+256*2072];
        fixed(byte* p=bytes)Check(Io(19,&id,8,p,bytes.Length),"read WAN links");
        uint count=BitConverter.ToUInt32(bytes,0);if(count>256)throw new InvalidDataException("Invalid WAN link count.");
        var links=new List<NdisWanLink>();
        for(int i=0;i<count;i++){
            int at=4+i*2072;uint length=BitConverter.ToUInt32(bytes,at+20);
            if(length<588||length>2048)continue;
            links.Add(new(bytes.AsSpan(at+14,6).ToArray(),bytes.AsSpan(at+8,6).ToArray(),bytes.AsSpan(at+24+584,4).ToArray()));
        }
        return links.ToArray();
    }
    [StructLayout(LayoutKind.Sequential,Pack=1)] struct Mode{public long Adapter;public uint Flags;}
    [StructLayout(LayoutKind.Sequential,Pack=1)] struct Request{public long Adapter;public IntPtr Buffer;}
    public uint GetMode(NdisAdapter adapter){var mode=new Mode{Adapter=adapter.Handle};Check(Io(13,&mode,12,&mode,12),"read adapter mode");return mode.Flags;}
    public void SetMode(NdisAdapter adapter,uint flags){var mode=new Mode{Adapter=adapter.Handle,Flags=flags};Check(Io(5,&mode,12,null,0),"set adapter mode");}
    public bool Read(NdisAdapter adapter,byte[] buffer)
    {
        if(buffer.Length!=BufferHeader+FrameCapacity)throw new ArgumentException("Invalid packet buffer.");
        fixed(byte* p=buffer){var request=new Request{Adapter=adapter.Handle,Buffer=(IntPtr)p};return Io(4,&request,16,&request,16);}
    }
    public void Send(NdisAdapter adapter,byte[] buffer,bool toStack)
    {
        if(buffer.Length!=BufferHeader+FrameCapacity||BitConverter.ToUInt32(buffer,20)>FrameCapacity)throw new ArgumentException("Invalid packet buffer.");
        fixed(byte* p=buffer){var request=new Request{Adapter=adapter.Handle,Buffer=(IntPtr)p};Check(Io(toStack?3:2,&request,16,null,0),"inject packet");}
    }
    public void SendFrame(NdisAdapter adapter,byte[] frame)
    {
        if(frame.Length>FrameCapacity)throw new InvalidDataException("Frame exceeds driver MTU.");
        var buffer=new byte[BufferHeader+FrameCapacity];BitConverter.GetBytes(1u).CopyTo(buffer,16);BitConverter.GetBytes((uint)frame.Length).CopyTo(buffer,20);frame.CopyTo(buffer,BufferHeader);Send(adapter,buffer,false);
    }
    public void Dispose()=>handle.Dispose();
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFileW(string name,uint access,uint sharing,IntPtr security,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool DeviceIoControl(SafeFileHandle file,uint code,IntPtr input,uint inputLength,IntPtr output,uint outputLength,out uint returned,IntPtr overlapped);
}
