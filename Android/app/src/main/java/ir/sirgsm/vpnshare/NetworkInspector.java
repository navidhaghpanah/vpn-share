package ir.sirgsm.vpnshare;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;

public final class NetworkInspector {
    private NetworkInspector() {}

    public static NetworkSnapshot inspect(Context context) {
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        if (manager == null) return new NetworkSnapshot(false, "", "", "Unavailable");
        String incoming = "Unknown";
        Network active = manager.getActiveNetwork();
        if (active != null) incoming = transport(manager.getNetworkCapabilities(active));
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities caps = manager.getNetworkCapabilities(network);
            if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
            LinkProperties links = manager.getLinkProperties(network);
            if (links == null) continue;
            String address = "";
            for (LinkAddress item : links.getLinkAddresses()) {
                if (!item.getAddress().isLoopbackAddress() && item.getAddress().getAddress().length == 4) {
                    address = item.getAddress().getHostAddress();
                    break;
                }
            }
            return new NetworkSnapshot(true, links.getInterfaceName(), address, incoming);
        }
        return new NetworkSnapshot(false, "", "", incoming);
    }

    static String transport(NetworkCapabilities caps) {
        if (caps == null) return "Disconnected";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_USB)) return "USB tethering";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "Ethernet";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "Wi-Fi";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "Mobile data";
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return "VPN";
        return "Other";
    }
}
