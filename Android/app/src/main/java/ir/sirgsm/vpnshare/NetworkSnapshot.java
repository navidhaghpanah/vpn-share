package ir.sirgsm.vpnshare;

import java.util.Objects;

public final class NetworkSnapshot {
    public final boolean vpnActive;
    public final String vpnInterface;
    public final String vpnAddress;
    public final String incoming;

    public NetworkSnapshot(boolean vpnActive, String vpnInterface, String vpnAddress, String incoming) {
        this.vpnActive = vpnActive;
        this.vpnInterface = safe(vpnInterface);
        this.vpnAddress = safe(vpnAddress);
        this.incoming = safe(incoming);
    }

    private static String safe(String value) { return Objects.requireNonNullElse(value, ""); }
}
