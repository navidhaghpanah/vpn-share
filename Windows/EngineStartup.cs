namespace VpnShare;

public static class EngineStartup
{
    public static IPacketEngine StartReady(Func<IPacketEngine> create)
    {
        var engine=create();
        try{
            engine.Start();
            if(engine.Faulted||!engine.Connected)throw new InvalidOperationException("Packet interfaces are not ready; client traffic remains blocked. Reconnection will retry.");
            return engine;
        }catch(Exception original){
            try{engine.Dispose();}catch(Exception cleanup){throw new AggregateException("Packet startup failed and adapter cleanup needs retry.",original,cleanup);}
            throw;
        }
    }
}
