using System.Diagnostics;
using System.Security.Principal;

namespace VpnShare;

internal static class RecoveryWatchdog
{
    static bool started;
    public static void Start()
    {
        if(started)return;
        using var parent=Process.GetCurrentProcess();
        var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true};
        if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory,"VPNShare.dll"));
        start.ArgumentList.Add("--watchdog");start.ArgumentList.Add(parent.Id.ToString());start.ArgumentList.Add(parent.StartTime.ToUniversalTime().Ticks.ToString());
        using var child=Process.Start(start)??throw new InvalidOperationException("The network recovery helper could not start.");started=true;
    }
    public static void Run(int pid,long ticks)
    {
        if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))return;
        try{using var parent=Process.GetProcessById(pid);if(parent.StartTime.ToUniversalTime().Ticks!=ticks)return;parent.WaitForExit();}catch(ArgumentException){}
        for(int attempt=0;attempt<3;attempt++){
            try{SharingSession.Recover();return;}
            catch(Exception e){
                try{File.AppendAllText(Path.Combine(Path.GetDirectoryName(NetworkSetup.StatePath)!,"recovery.log"),$"{DateTime.UtcNow:O} {e.Message}{Environment.NewLine}");}catch{}
                Thread.Sleep(1500);
            }
        }
        // The journal and persistent blocking rules remain for the next launch.
    }
}
