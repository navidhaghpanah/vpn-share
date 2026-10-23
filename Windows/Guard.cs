using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace VpnShare;

// Static persistent WFP blocks survive UI termination. In custom mode, originals
// are blocked here. NDIS receives client frames before IP routing and injects
// translated Ethernet frames directly into the selected VPN packet interface.
public static class Guard
{
    static readonly Guid Forward4=new("a82acc24-4ee1-4ee1-b465-fd1d25cb10a4");
    static readonly Guid Forward6=new("7b964818-19c7-493a-b71f-832c3684d28c");
    static readonly Guid Out4=new("1e5c9fae-8a84-4135-a331-950b54229ecd");
    static readonly Guid SourceIf=new("2311334d-c92d-45bf-9496-edf447820e2d");
    static readonly Guid DestinationIf=new("35cf6522-4139-45ee-a0d5-67b80949d879");
    static readonly Guid LocalIf=new("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
    static readonly Guid LocalIp=new("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
    static readonly Guid SubLayer=new("eebecc03-ced4-4380-819a-273439c8e20f");

    public static void Install(SessionState state, Action persist)
    {
        Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out var engine));
        try {
            var sub=new SubLayer0 { Key=SubLayer, Display=new Display0 {Name="VPN Share guard"}, Flags=1, Weight=0 };
            var result=FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero);
            if(result!=0 && result!=0x80320009) Check(result);
            var down=new Condition0{Key=SourceIf,Value=new Value0{Type=3,Data=(ulong)state.DownstreamIndex}};
            if(state.UseWindowsKernel){
                Add(engine,Forward4,new[]{down,new Condition0{Key=DestinationIf,Match=10,Value=new Value0{Type=3,Data=(ulong)state.VpnIndex}}},state,persist);
                Add(engine,Forward6,new[]{down},state,persist);
            }else foreach(var layer in new[]{Forward4,Forward6})Add(engine,layer,new[]{down},state,persist);
            InstallVpn(engine,state,persist);
        } finally { FwpmEngineClose0(engine); }
    }
    public static void InstallVpn(SessionState state,Action persist)
    {
        Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out var engine));
        bool transaction=false;
        try{
            var prior=state.VpnGuardKeys.ToArray();
            Check(FwpmTransactionBegin0(engine,0));transaction=true;
            InstallVpn(engine,state,persist);
            foreach(var key in prior){var copy=key;uint result=FwpmFilterDeleteByKey0(engine,ref copy);if(result!=0&&result!=0x80320003)Check(result);}
            Check(FwpmTransactionCommit0(engine));transaction=false;
            foreach(var key in prior){state.GuardKeys.Remove(key);state.VpnGuardKeys.Remove(key);}
            persist();
        }finally{if(transaction)FwpmTransactionAbort0(engine);FwpmEngineClose0(engine);}
    }
    static void InstallVpn(IntPtr engine,SessionState state,Action persist)
    {
            Check(ConvertInterfaceIndexToLuid((uint)state.VpnIndex,out var luid));
            var memory=Marshal.AllocHGlobal(8);
            try {
                Marshal.WriteInt64(memory,unchecked((long)luid));
                Add(engine,Out4,new[]{
                    new Condition0 {Key=LocalIp,Value=new Value0 {Type=3,Data=Packets.Ip(IPAddress.Parse(state.VpnIp))}},
                    new Condition0 {Key=LocalIf,Match=10,Value=new Value0 {Type=4,Data=(ulong)memory.ToInt64()}}
                },state,persist,true);
            } finally {Marshal.FreeHGlobal(memory);}
    }
    static void Add(IntPtr engine,Guid layer,Condition0[] conditions,SessionState state,Action persist,bool vpn=false)
    {
        Guid key=Guid.NewGuid();
        // Journal before mutation, so a crash never leaves an untracked filter.
        state.GuardKeys.Add(key);if(vpn)state.VpnGuardKeys.Add(key);persist();
        int size=Marshal.SizeOf<Condition0>();
        var memory=Marshal.AllocHGlobal(size*conditions.Length);
        try {
            for(int i=0;i<conditions.Length;i++) Marshal.StructureToPtr(conditions[i],memory+i*size,false);
            var filter=new Filter0 {Key=key, Display=new Display0 {Name="VPN Share fail-closed"}, Flags=1,
                Layer=layer, SubLayer=SubLayer, ConditionCount=(uint)conditions.Length, Conditions=memory,
                Action=new Action0 {Type=0x1001} };
            Check(FwpmFilterAdd0(engine,ref filter,IntPtr.Zero,out _));
        } finally {Marshal.FreeHGlobal(memory);}
    }
    public static void Remove(SessionState state,Action persist)
    {
        Check(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out var engine));
        try {
            foreach(var key in state.GuardKeys.ToArray()) {
                var copy=key; uint result=FwpmFilterDeleteByKey0(engine,ref copy);
                if(result!=0 && result!=0x80320003) Check(result);
                state.GuardKeys.Remove(key);state.VpnGuardKeys.Remove(key);persist();
            }
        } finally {FwpmEngineClose0(engine);}
    }
    static void Check(uint error) {if(error!=0) throw new Win32Exception(unchecked((int)error),$"WFP operation failed (0x{error:x8}). Sharing was not enabled.");}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Display0 { [MarshalAs(UnmanagedType.LPWStr)] public string? Name; [MarshalAs(UnmanagedType.LPWStr)] public string? Description; }
    [StructLayout(LayoutKind.Explicit,Size=16)] struct Value0 { [FieldOffset(0)] public uint Type; [FieldOffset(8)] public ulong Data; }
    [StructLayout(LayoutKind.Sequential)] struct Condition0 { public Guid Key; public uint Match; public Value0 Value; }
    [StructLayout(LayoutKind.Sequential)] struct Action0 { public uint Type; public Guid Key; }
    [StructLayout(LayoutKind.Explicit,Size=16)] struct Context0 { [FieldOffset(0)] public ulong Raw; }
    [StructLayout(LayoutKind.Sequential)] struct Blob0 {public uint Size; public IntPtr Data;}
    [StructLayout(LayoutKind.Sequential)] struct SubLayer0 {public Guid Key; public Display0 Display; public uint Flags; public IntPtr Provider; public Blob0 Data; public ushort Weight;}
    [StructLayout(LayoutKind.Sequential)] struct Filter0 {
        public Guid Key; public Display0 Display; public uint Flags; public IntPtr Provider; public Blob0 Data;
        public Guid Layer,SubLayer; public Value0 Weight; public uint ConditionCount; public IntPtr Conditions;
        public Action0 Action; public Context0 Context; public IntPtr Reserved; public ulong FilterId; public Value0 EffectiveWeight;
    }
    [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string? server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine,ref SubLayer0 sub,IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine,ref Filter0 filter,IntPtr security,out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine,ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine,uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("iphlpapi.dll")] static extern uint ConvertInterfaceIndexToLuid(uint index,out ulong luid);
}
