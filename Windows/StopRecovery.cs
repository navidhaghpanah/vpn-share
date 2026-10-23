namespace VpnShare;

public static class StopRecovery
{
    public static void Run(Action releaseEngine,Action restoreJournal)
    {
        Exception? releaseError=null;
        try{releaseEngine();}catch(Exception e){releaseError=e;}
        try{restoreJournal();}
        catch(Exception recoveryError){
            if(releaseError!=null)throw new AggregateException("Engine shutdown and journal recovery failed. Protection is retained.",releaseError,recoveryError);
            throw;
        }
    }
}
