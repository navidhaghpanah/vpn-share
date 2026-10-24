namespace VpnShare;

// Single-flight work runs without the UI synchronization context. Callers snapshot
// control values first, and marshal progress back through their existing UI handler.
public sealed class OperationWorker
{
    int running;
    public async Task<bool> TryRunAsync(Func<Task> work)
    {
        if(Interlocked.CompareExchange(ref running,1,0)!=0)return false;
        try{await Task.Run(work);return true;}
        finally{Volatile.Write(ref running,0);}
    }
}
