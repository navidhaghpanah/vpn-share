package ir.sirgsm.vpnshare;

import org.junit.Test;
import static org.junit.Assert.*;

public final class RootSharingPlanTest {
    @Test public void findsPrivateHotspotAndCalculatesSubnet() {
        String output = "10: tun0    inet 10.8.0.2/24 scope global tun0\n" +
            "22: ap0    inet 192.168.43.1/24 brd 192.168.43.255 scope global ap0\n";
        RootSharingPlan.Hotspot found = RootSharingPlan.findHotspot(output, "tun0");
        assertNotNull(found);
        assertEquals("ap0", found.interfaceName());
        assertEquals("192.168.43.0/24", found.cidr());
    }

    @Test public void ignoresUnrelatedWifiAndPublicAddresses() {
        String output = "2: wlan0 inet 192.168.1.9/24 scope global wlan0\n" +
            "3: ap0 inet 8.8.8.8/24 scope global ap0\n";
        assertNull(RootSharingPlan.findHotspot(output, "tun0"));
    }

    @Test public void acceptsWlanZeroWhenItIsTheHotspotGateway() {
        String output = "2: wlan0 inet 192.168.232.1/24 scope global wlan0\n";
        RootSharingPlan.Hotspot found = RootSharingPlan.findHotspot(output, "tun0");
        assertNotNull(found);
        assertEquals("wlan0", found.interfaceName());
        assertEquals("192.168.232.0/24", found.cidr());
    }

    @Test public void rejectsWlanClientAddressThatIsNotGateway() {
        String output = "2: wlan0 inet 192.168.1.42/24 scope global wlan0\n";
        assertNull(RootSharingPlan.findHotspot(output, "tun0"));
    }

    @Test public void scriptIsFailClosedAndBlocksIpv6() {
        String script = RootSharingPlan.startScript("tun0", new RootSharingPlan.Hotspot("ap0", "192.168.43.0/24"));
        assertTrue(script.contains("-i ap0 ! -o tun0 -j REJECT"));
        assertTrue(script.contains("ip6tables"));
        assertTrue(script.contains("MASQUERADE"));
        assertTrue(script.contains("set -eu"));
        assertTrue(script.contains("-C VPNSHARE_NAT"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsShellInjectionInInterface() {
        RootSharingPlan.startScript("tun0;reboot", new RootSharingPlan.Hotspot("ap0", "192.168.43.0/24"));
    }

    @Test public void cleanupVerifiesThatHooksAreGone() {
        String cleanup = RootSharingPlan.cleanupScript();
        assertTrue(cleanup.contains("cleanup_ok=0"));
        assertTrue(cleanup.contains("[ \"$cleanup_ok\" -eq 1 ] || exit 41"));
        assertFalse(cleanup.trim().endsWith("|| true"));
    }
}
