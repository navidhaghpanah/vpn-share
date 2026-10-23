using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace VpnShare;

internal sealed class WidgetSettings
{
    public string Ssid{get;set;}="Navid VPN";
    public string Password{get;set;}="VPN-"+Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
    public string Dns{get;set;}="";
    public string WifiOutput{get;set;}="auto";
    static string FilePath=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"VPNShare","preferences.json");
    public static WidgetSettings Load()
    {
        try{
            var saved=JsonSerializer.Deserialize<Saved>(File.ReadAllText(FilePath));if(saved==null)return new();
            return new WidgetSettings{Ssid=saved.Ssid,Dns=saved.Dns,WifiOutput=saved.WifiOutput,Password=Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(saved.Secret),null,DataProtectionScope.CurrentUser))};
        }catch{return new();}
    }
    public void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var data=new Saved{Ssid=Ssid,Dns=Dns,WifiOutput=WifiOutput,Secret=Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(Password),null,DataProtectionScope.CurrentUser))};
        string temporary=FilePath+".tmp";File.WriteAllText(temporary,JsonSerializer.Serialize(data));File.Move(temporary,FilePath,true);
    }
    sealed class Saved{public string Ssid{get;set;}="Navid VPN";public string Dns{get;set;}="";public string WifiOutput{get;set;}="auto";public string Secret{get;set;}="";}
}
