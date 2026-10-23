namespace VpnShare;

public interface IPacketEngine : IDisposable
{
    bool Connected{get;}
    bool Faulted{get;}
    long Uploaded{get;}
    long Downloaded{get;}
    long Dropped{get;}
    int Flows{get;}
    event Action<string>? Message;
    event Action<Exception>? Fault;
    void Start();
}

