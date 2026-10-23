using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace VpnShare;

public sealed record AdapterInfo(string Id, string Name, string Description, int Index,
    string Kind, bool Connected, string[] IPv4, string[] Dns, string[] Gateways, int Mtu)
{
    public override string ToString() => $"{Name}  ·  {Kind}  ·  {(Connected ? string.Join(", ", IPv4) : "disconnected")}";
    public bool IsVpn => Kind == "VPN";
}

public static class AdapterCatalog
{
    public static AdapterInfo[] Read() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        .Select(n => {
            var props = n.GetIPProperties();
            IPv4InterfaceProperties? v4 = null;
            try { v4 = props.GetIPv4Properties(); } catch (NetworkInformationException) { }
            var vpn = n.NetworkInterfaceType is NetworkInterfaceType.Ppp or NetworkInterfaceType.Tunnel ||
                Regex.IsMatch(n.Name + " " + n.Description, @"wireguard|wintun|\btun\b|\btap\b|vpn|anyconnect|fortinet|tailscale|zerotier", RegexOptions.IgnoreCase);
            var kind = vpn ? "VPN" : Regex.IsMatch(n.Description, "RNDIS|Remote NDIS|USB.*Ethernet|Mobile.*USB", RegexOptions.IgnoreCase)
                ? "USB tethering" : n.Description.Contains("Wi-Fi Direct", StringComparison.OrdinalIgnoreCase) || n.Description.Contains("Hosted Network",StringComparison.OrdinalIgnoreCase) ? "Hotspot virtual"
                : n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? "Wi-Fi"
                : "Ethernet / virtual";
            return new AdapterInfo(n.Id, n.Name, n.Description, v4?.Index ?? 0, kind,
                n.OperationalStatus == OperationalStatus.Up,
                props.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork).Select(a => a.Address.ToString()).ToArray(),
                props.DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()).ToArray(),
                props.GatewayAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork).Select(a => a.Address.ToString()).ToArray(),
                v4?.Mtu ?? 1500);
        }).OrderByDescending(n => n.Connected && n.IsVpn).ThenBy(n => n.Name).ToArray();

    public static AdapterInfo[] ReadPhysicalDevices()
    {
        var json=NetworkSetup.Run("ConvertTo-Json -InputObject @(Get-NetAdapter -Physical | ForEach-Object {[pscustomobject]@{Id=[string]$_.InterfaceGuid; Name=$_.Name; Description=$_.InterfaceDescription; Index=[int]$_.ifIndex; Wireless=([string]$_.MediaType -match '802.11'); Connected=([string]$_.Status -eq 'Up')}}) -Compress");
        var values=System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement[]>(json)??Array.Empty<System.Text.Json.JsonElement>();
        var current=Read();
        return values.Select(x=>current.FirstOrDefault(a=>a.Id.Trim('{','}').Equals(x.GetProperty("Id").GetString()!.Trim('{','}'),StringComparison.OrdinalIgnoreCase)) ??
            new AdapterInfo(x.GetProperty("Id").GetString()!,x.GetProperty("Name").GetString()!,x.GetProperty("Description").GetString()!,x.GetProperty("Index").GetInt32(),
                x.GetProperty("Wireless").GetBoolean()?"Wi-Fi":"Ethernet / virtual",x.GetProperty("Connected").GetBoolean(),Array.Empty<string>(),Array.Empty<string>(),Array.Empty<string>(),1500)).ToArray();
    }

    public static IPAddress VpnAddress(AdapterInfo adapter) => adapter.IPv4.Select(IPAddress.Parse)
        .FirstOrDefault(a => !a.ToString().StartsWith("169.254.") && !a.Equals(IPAddress.Any))
        ?? throw new InvalidOperationException("The selected VPN has no usable IPv4 address.");
}
