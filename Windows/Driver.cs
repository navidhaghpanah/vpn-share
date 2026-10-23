namespace VpnShare;

public static class DriverFiles
{
    public static bool Available=>NdisDevice.Available;
    public static string Check()=>Available
        ? "Windows Packet Filter is available. Custom NAT uses its signed NDIS driver. Client traffic still requires a live hardware test."
        : "Personal-use Windows Packet Filter installs on Start from its official source. Administrator permission and internet access are required; Windows may request a restart.";
}
