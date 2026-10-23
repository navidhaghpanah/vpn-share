using System.Diagnostics;
using System.Text.RegularExpressions;

namespace VpnShare;

public sealed record ExternalVpnStatus(string Provider,string Protocol)
{
    public static ExternalVpnStatus? ParseExpressVpn(string output)
    {
        // A running process or a line saying Disconnected/Connecting is not
        // evidence of an established VPN. Only the vendor's connected state is.
        if(output.Length>8192||!Regex.IsMatch(output,@"^Connected(?:[ \t]+to[ \t]+[^\r\n]+)?[ \t]*\r?$",RegexOptions.Multiline|RegexOptions.IgnoreCase))return null;
        var match=Regex.Match(output,@"^Protocol in use:[ \t]*([A-Za-z0-9 -]{1,40})[ \t]*\r?$",RegexOptions.Multiline|RegexOptions.IgnoreCase);
        return new("ExpressVPN",match.Success?match.Groups[1].Value.Trim():"unknown protocol");
    }
    public static ExternalVpnStatus? ReadExpressVpn()
    {
        string path=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"ExpressVPN","expressvpnctl.exe");
        if(!File.Exists(path))return null;
        try{
            using var process=new Process{StartInfo=new(path){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true}};
            process.StartInfo.ArgumentList.Add("--timeout");process.StartInfo.ArgumentList.Add("2");process.StartInfo.ArgumentList.Add("status");
            if(!process.Start())return null;
            var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
            if(!process.WaitForExit(3000)){process.Kill(true);return null;}
            Task.WaitAll(output,error);
            return process.ExitCode==0?ParseExpressVpn(output.Result):null;
        }catch(Exception e)when(e is IOException or System.ComponentModel.Win32Exception or InvalidOperationException or UnauthorizedAccessException){return null;}
    }
}
