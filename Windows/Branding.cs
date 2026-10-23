using System.Reflection;
using System.Text.Json;

namespace VpnShare;

public static class Branding
{
    static readonly JsonElement Data=Load();
    static JsonElement Load(){using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("VpnShare.About.json")??throw new InvalidDataException("About metadata is missing.");using var document=JsonDocument.Parse(stream);return document.RootElement.Clone();}
    public static string Version=>Data.GetProperty("version").GetString()!;
    public static string Author=>Data.GetProperty("author").GetString()!;
    public static string Website=>Data.GetProperty("website").GetString()!;
    public static string Phone=>Data.GetProperty("phone").GetString()!;
    public static string Telegram=>Data.GetProperty("telegram").GetString()!;
}
