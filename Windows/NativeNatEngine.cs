namespace VpnShare;

// Removal only, for interrupted older journals. New sessions cannot create WinNAT.
internal static class NativeNatEngine
{
    public static void Remove(SessionState state)
    {
        string name=state.NativeNatName;if(string.IsNullOrEmpty(name))return;
        if(!name.StartsWith("VPNShare-")||!Guid.TryParseExact(name[9..],"N",out _))throw new InvalidOperationException("Invalid legacy app-owned NAT identifier.");
        NetworkSetup.Run($"Get-NetNat -Name '{name}' -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false");
    }
}
