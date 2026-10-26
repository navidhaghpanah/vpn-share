package ir.sirgsm.vpnshare;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class RootSharingPlan {
    private static final Pattern INTERFACE = Pattern.compile("[A-Za-z0-9_.-]{1,15}");
    private static final Pattern ADDRESS = Pattern.compile("^\\d+:\\s+([^ ]+)\\s+inet\\s+([0-9.]+)/(\\d+).*$");

    private RootSharingPlan() {}

    public record Hotspot(String interfaceName, String cidr) {}

    public static Hotspot findHotspot(String ipOutput, String vpnInterface) {
        for (String line : ipOutput.split("\\R")) {
            Matcher match = ADDRESS.matcher(line.trim());
            if (!match.matches()) continue;
            String name = match.group(1).replaceAll("@.*$", "");
            String address = match.group(2);
            int prefix = Integer.parseInt(match.group(3));
            if (name.equals(vpnInterface) || name.equals("lo") || prefix < 8 || prefix > 30) continue;
            if (!isPrivate(address)) continue;
            String lower = name.toLowerCase(Locale.ROOT);
            boolean hotspotName = lower.startsWith("ap") || lower.contains("softap") || lower.startsWith("swlan") || lower.matches("wlan\\d+");
            boolean looksLikeGateway = address.endsWith(".1");
            if (hotspotName && looksLikeGateway) {
                return new Hotspot(name, networkCidr(address, prefix));
            }
        }
        return null;
    }

    public static String startScript(String vpn, Hotspot hotspot) {
        validateInterface(vpn);
        validateInterface(hotspot.interfaceName());
        validateCidr(hotspot.cidr());
        String down = hotspot.interfaceName();
        String cidr = hotspot.cidr();
        return cleanupScript()
            + "\nset -eu"
            + "\nsettings put global tether_offload_disabled 1"
            + "\niptables -w -N VPNSHARE_NAT 2>/dev/null || true"
            + "\niptables -w -t nat -N VPNSHARE_NAT 2>/dev/null || true"
            + "\niptables -w -F VPNSHARE_NAT"
            + "\niptables -w -t nat -F VPNSHARE_NAT"
            + "\niptables -w -A VPNSHARE_NAT -i " + down + " ! -o " + vpn + " -j REJECT"
            + "\niptables -w -I FORWARD 1 -j VPNSHARE_NAT"
            + "\niptables -w -A VPNSHARE_NAT -i " + down + " -o " + vpn + " -s " + cidr + " -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT"
            + "\niptables -w -A VPNSHARE_NAT -i " + vpn + " -o " + down + " -d " + cidr + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
            + "\niptables -w -t nat -A VPNSHARE_NAT -s " + cidr + " -o " + vpn + " -j MASQUERADE"
            + "\niptables -w -t nat -I POSTROUTING 1 -j VPNSHARE_NAT"
            + "\nip6tables -w -N VPNSHARE_V6 2>/dev/null || true"
            + "\nip6tables -w -F VPNSHARE_V6"
            + "\nip6tables -w -A VPNSHARE_V6 -i " + down + " -j REJECT"
            + "\nip6tables -w -I FORWARD 1 -j VPNSHARE_V6"
            + "\nsysctl -w net.ipv4.ip_forward=1 >/dev/null"
            + "\niptables -w -C FORWARD -j VPNSHARE_NAT"
            + "\niptables -w -C VPNSHARE_NAT -i " + down + " ! -o " + vpn + " -j REJECT"
            + "\niptables -w -t nat -C POSTROUTING -j VPNSHARE_NAT"
            + "\niptables -w -t nat -C VPNSHARE_NAT -s " + cidr + " -o " + vpn + " -j MASQUERADE"
            + "\nip6tables -w -C FORWARD -j VPNSHARE_V6"
            + "\nip6tables -w -C VPNSHARE_V6 -i " + down + " -j REJECT";
    }

    public static String cleanupScript() {
        return "command -v iptables >/dev/null 2>&1 || exit 40"
            + "\ncommand -v ip6tables >/dev/null 2>&1 || exit 40"
            + "\ncleanup_ok=1"
            + "\nwhile iptables -w -C FORWARD -j VPNSHARE_NAT 2>/dev/null; do iptables -w -D FORWARD -j VPNSHARE_NAT || { cleanup_ok=0; break; }; done"
            + "\nwhile iptables -w -t nat -C POSTROUTING -j VPNSHARE_NAT 2>/dev/null; do iptables -w -t nat -D POSTROUTING -j VPNSHARE_NAT || { cleanup_ok=0; break; }; done"
            + "\nif iptables -w -L VPNSHARE_NAT >/dev/null 2>&1; then iptables -w -F VPNSHARE_NAT && iptables -w -X VPNSHARE_NAT || cleanup_ok=0; fi"
            + "\nif iptables -w -t nat -L VPNSHARE_NAT >/dev/null 2>&1; then iptables -w -t nat -F VPNSHARE_NAT && iptables -w -t nat -X VPNSHARE_NAT || cleanup_ok=0; fi"
            + "\nwhile ip6tables -w -C FORWARD -j VPNSHARE_V6 2>/dev/null; do ip6tables -w -D FORWARD -j VPNSHARE_V6 || { cleanup_ok=0; break; }; done"
            + "\nif ip6tables -w -L VPNSHARE_V6 >/dev/null 2>&1; then ip6tables -w -F VPNSHARE_V6 && ip6tables -w -X VPNSHARE_V6 || cleanup_ok=0; fi"
            + "\niptables -w -C FORWARD -j VPNSHARE_NAT >/dev/null 2>&1 && cleanup_ok=0 || true"
            + "\niptables -w -t nat -C POSTROUTING -j VPNSHARE_NAT >/dev/null 2>&1 && cleanup_ok=0 || true"
            + "\nip6tables -w -C FORWARD -j VPNSHARE_V6 >/dev/null 2>&1 && cleanup_ok=0 || true"
            + "\n[ \"$cleanup_ok\" -eq 1 ] || exit 41";
    }

    private static void validateInterface(String value) {
        if (value == null || !INTERFACE.matcher(value).matches()) throw new IllegalArgumentException("Unsafe interface name");
    }

    private static void validateCidr(String value) {
        if (value == null || !value.matches("[0-9.]+/(?:[89]|[12][0-9]|30)")) throw new IllegalArgumentException("Unsafe subnet");
        try { if (!(InetAddress.getByName(value.substring(0, value.indexOf('/'))) instanceof Inet4Address)) throw new Exception(); }
        catch (Exception error) { throw new IllegalArgumentException("Invalid subnet"); }
    }

    private static boolean isPrivate(String ip) {
        String[] p = ip.split("\\.");
        if (p.length != 4) return false;
        int a = Integer.parseInt(p[0]), b = Integer.parseInt(p[1]);
        return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168);
    }

    private static String networkCidr(String ip, int prefix) {
        String[] p = ip.split("\\.");
        long value = 0;
        for (String item : p) value = (value << 8) | Integer.parseInt(item);
        long mask = 0xffffffffL << (32 - prefix) & 0xffffffffL;
        long network = value & mask;
        return ((network >>> 24) & 255) + "." + ((network >>> 16) & 255) + "." + ((network >>> 8) & 255) + "." + (network & 255) + "/" + prefix;
    }
}
