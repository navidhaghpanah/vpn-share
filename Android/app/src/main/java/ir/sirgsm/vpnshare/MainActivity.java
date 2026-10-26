package ir.sirgsm.vpnshare;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class MainActivity extends Activity {
    private static final String PREFS = "vpn_share_state";
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private final AtomicBoolean busy = new AtomicBoolean();
    private volatile boolean waitingForHotspotSettings;
    private volatile boolean hotspotSettingsWasPaused;
    private TetheringController tethering;
    private NetworkSnapshot snapshot = new NetworkSnapshot(false, "", "", "Unknown");
    private TextView vpnState, vpnDetails, incoming, rootState, message;
    private Button share;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        tethering = new TetheringController(this);
        setContentView(buildUi());
        share.setText(getPreferences().getBoolean("active", false) ? "Stop sharing" : "Start sharing");
        recoverIfNeeded();
        refresh();
    }

    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }

    @Override protected void onPause() {
        if (waitingForHotspotSettings) hotspotSettingsWasPaused = true;
        super.onPause();
    }

    @Override protected void onResume() {
        super.onResume();
        if (!waitingForHotspotSettings || !hotspotSettingsWasPaused) return;
        waitingForHotspotSettings = false;
        hotspotSettingsWasPaused = false;
        setBusy(true, "Checking the hotspot…");
        worker.execute(() -> {
            sleep(1200);
            finishRootStart(RootShell.available());
        });
    }

    private View buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackground(gradient(0xff0b2636, 0xff172044, 0));
        LinearLayout root = column(24);
        root.setPadding(dp(22), dp(18), dp(22), dp(22));
        scroll.addView(root);

        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        ImageView icon = new ImageView(this);
        icon.setImageResource(ir.sirgsm.vpnshare.R.drawable.app_icon);
        header.addView(icon, new LinearLayout.LayoutParams(dp(48), dp(48)));
        LinearLayout titleBox = column(0);
        TextView title = text("VPN Share", 30, Color.WHITE, Typeface.BOLD);
        TextView subtitle = text("A PRIVATE CONNECTION. SHARED.", 11, 0xff9ec8ed, Typeface.NORMAL);
        titleBox.addView(title); titleBox.addView(subtitle);
        LinearLayout.LayoutParams titleParams = new LinearLayout.LayoutParams(0, -2, 1);
        titleParams.setMargins(dp(10), 0, 0, 0);
        header.addView(titleBox, titleParams);
        Button about = button("About", false);
        about.setOnClickListener(v -> showAbout());
        header.addView(about, new LinearLayout.LayoutParams(dp(86), dp(44)));
        root.addView(header);

        LinearLayout vpnCard = card();
        vpnState = text("CHECKING VPN…", 14, 0xff65f4e7, Typeface.BOLD);
        vpnDetails = text("Scanning Android networks", 17, Color.WHITE, Typeface.NORMAL);
        incoming = text("Incoming: —", 13, 0xffa9cbed, Typeface.NORMAL);
        vpnCard.addView(vpnState); vpnCard.addView(space(14)); vpnCard.addView(vpnDetails); vpnCard.addView(space(10)); vpnCard.addView(incoming);
        root.addView(vpnCard, cardParams());

        LinearLayout shareCard = card();
        shareCard.addView(text("Share through", 18, Color.WHITE, Typeface.BOLD));
        shareCard.addView(space(12));
        shareCard.addView(text("Wi-Fi hotspot → active VPN", 16, 0xffd4edff, Typeface.BOLD));
        shareCard.addView(space(8));
        shareCard.addView(text("Protected sharing of another app's VPN requires root. Android 16 can start tethering through its public API; Android 8–15 may require the system hotspot panel.", 13, 0xffa9cbed, Typeface.NORMAL));
        shareCard.addView(space(14));
        rootState = text("Root: checking…", 13, 0xffffcc80, Typeface.BOLD);
        shareCard.addView(rootState);
        root.addView(shareCard, cardParams());

        share = button("Start sharing", true);
        share.setContentDescription("Start or stop VPN sharing");
        share.setOnClickListener(v -> toggle());
        LinearLayout.LayoutParams actionParams = new LinearLayout.LayoutParams(-1, dp(58));
        actionParams.setMargins(0, dp(16), 0, dp(10));
        root.addView(share, actionParams);
        message = text("Ready. Connect a VPN first.", 13, 0xffffd180, Typeface.NORMAL);
        root.addView(message);

        LinearLayout controls = new LinearLayout(this);
        controls.setGravity(Gravity.CENTER);
        Button refresh = button("Refresh", false);
        refresh.setOnClickListener(v -> refresh());
        Button settings = button("Hotspot settings", false);
        settings.setOnClickListener(v -> tethering.openSettings());
        controls.addView(refresh, new LinearLayout.LayoutParams(0, dp(48), 1));
        LinearLayout.LayoutParams settingsParams = new LinearLayout.LayoutParams(0, dp(48), 1);
        settingsParams.setMargins(dp(10), 0, 0, 0);
        controls.addView(settings, settingsParams);
        LinearLayout.LayoutParams controlsParams = new LinearLayout.LayoutParams(-1, -2);
        controlsParams.setMargins(0, dp(16), 0, 0);
        root.addView(controls, controlsParams);

        LinearLayout footer = new LinearLayout(this);
        footer.setGravity(Gravity.CENTER_VERTICAL);
        TextView version = text("ANDROID / 0.1.0-alpha.2", 10, 0xff82a7c8, Typeface.NORMAL);
        TextView site = text("sirgsm.ir", 12, 0xff65f4e7, Typeface.BOLD);
        site.setPadding(dp(12), dp(18), dp(12), dp(18));
        site.setOnClickListener(v -> open("https://sirgsm.ir"));
        TextView nh = text("NH", 11, 0xff9ec8ed, Typeface.BOLD);
        footer.addView(version, new LinearLayout.LayoutParams(0, -2, 1));
        footer.addView(site); footer.addView(nh);
        root.addView(footer);
        return scroll;
    }

    private void refresh() {
        if (!busy.compareAndSet(false, true)) return;
        setBusy(true, "Checking networks…");
        worker.execute(() -> {
            NetworkSnapshot found = NetworkInspector.inspect(this);
            boolean rooted = RootShell.available();
            main.post(() -> {
                snapshot = found;
                vpnState.setText(found.vpnActive ? "● VPN DETECTED" : "○ WAITING FOR VPN");
                vpnState.setTextColor(found.vpnActive ? 0xff65f4e7 : 0xffffcc80);
                vpnDetails.setText(found.vpnActive ? found.vpnInterface + (found.vpnAddress.isEmpty() ? "" : "  ·  " + found.vpnAddress) : "Connect your VPN app, then refresh.");
                incoming.setText(getString(R.string.incoming_format, found.incoming));
                rootState.setText(rooted ? "Root: available — protected NAT can be enabled" : "Root: required — protected sharing is unavailable");
                rootState.setTextColor(rooted ? 0xff65f4e7 : 0xffffcc80);
                message.setText(found.vpnActive ? "VPN ready. Start sharing when the hotspot radio is available." : "No active VPN was found.");
                busy.set(false); setBusy(false, null);
            });
        });
    }

    private void toggle() {
        boolean active = getPreferences().getBoolean("active", false);
        if (active) stopSharing(); else startSharing();
    }

    private void startSharing() {
        if (!snapshot.vpnActive || snapshot.vpnInterface.isEmpty()) { message.setText(R.string.connect_vpn_first); return; }
        if (!busy.compareAndSet(false, true)) { message.setText(R.string.operation_running); return; }
        setBusy(true, "Starting hotspot…");
        worker.execute(() -> {
            boolean rooted = RootShell.available();
            if (!rooted) {
                finishOperation(false, "Root access was not granted. Android cannot route another app's VPN into hotspot safely without root.");
                return;
            }
            prepareRootJournal();
            if (!tethering.canStartDirectly()) {
                if (rooted) {
                    RootShell.run("cmd connectivity tether start 2>/dev/null || cmd wifi start-softap 2>/dev/null || true", 8);
                    sleep(2200);
                    RootSharingPlan.Hotspot hotspot = findHotspot();
                    if (hotspot != null) {
                        finishRootStart(hotspot);
                        return;
                    }
                }
                waitingForHotspotSettings = true;
                hotspotSettingsWasPaused = false;
                main.post(() -> {
                    message.setText("Turn on Wi-Fi hotspot, then return to VPN Share.");
                    tethering.openSettings();
                });
                return;
            }
            tethering.start(worker, (started, detail) -> {
                if (!started) { if (rooted) restoreRootSystemState(); finishOperation(false, detail + " Open Hotspot settings and retry."); return; }
                sleep(2000);
                finishRootStart(rooted);
            });
        });
    }

    private void finishRootStart(boolean rooted) {
        if (!rooted) {
            failAndStopHotspot("Android cannot guarantee VPN forwarding without root. The unprotected app-owned hotspot was stopped.");
            return;
        }
        RootSharingPlan.Hotspot hotspot = findHotspot();
        if (hotspot == null) {
            restoreRootSystemState();
            failAndStopHotspot("Hotspot interface was not found. Turn on Wi-Fi hotspot, then press Start sharing again.");
            return;
        }
        finishRootStart(hotspot);
    }

    private RootSharingPlan.Hotspot findHotspot() {
        RootShell.Result links = RootShell.run("ip -o -4 addr show scope global", 6);
        if (links.code() != 0) return null;
        return RootSharingPlan.findHotspot(links.output(), snapshot.vpnInterface);
    }

    private void finishRootStart(RootSharingPlan.Hotspot hotspot) {
        RootShell.Result result;
        try { result = RootShell.run(RootSharingPlan.startScript(snapshot.vpnInterface, hotspot), 15); }
        catch (RuntimeException error) { result = new RootShell.Result(-1, error.getMessage()); }
        if (result.code() != 0) {
            restoreRootSystemState();
            failAndStopHotspot("Protected NAT failed: " + concise(result.output()));
            return;
        }
        getPreferences().edit().putBoolean("active", true).putBoolean("recovery_pending", false).putString("vpn", snapshot.vpnInterface).putString("downstream", hotspot.interfaceName()).apply();
        finishOperation(true, "Sharing through " + snapshot.vpnInterface + ". Leak protection is active.");
    }

    private void stopSharing() {
        if (!busy.compareAndSet(false, true)) return;
        setBusy(true, "Restoring network…");
        worker.execute(() -> {
            RootShell.Result cleaned = restoreRootSystemState();
            tethering.stop(worker, (ignored, detail) -> finishOperation(false, cleaned.code() == 0 ? "Sharing stopped. Network rules restored." : "Rules need attention: " + concise(cleaned.output())));
        });
    }

    private void recoverIfNeeded() {
        if (!getPreferences().getBoolean("recovery_pending", false)) return;
        message.setText(R.string.recovering_operation);
        worker.execute(() -> {
            RootShell.Result result = restoreRootSystemState();
            main.post(() -> message.setText(result.code() == 0 ? "Interrupted rules were restored." : "Recovery needs root access: " + concise(result.output())));
        });
    }

    private void prepareRootJournal() {
        RootShell.Result forwarding = RootShell.run("cat /proc/sys/net/ipv4/ip_forward", 5);
        RootShell.Result offload = RootShell.run("settings get global tether_offload_disabled", 5);
        getPreferences().edit()
            .putBoolean("recovery_pending", true)
            .putString("previous_forwarding", forwarding.code() == 0 ? forwarding.output().trim() : "1")
            .putString("previous_offload", offload.code() == 0 ? offload.output().trim() : "null")
            .apply();
        RootShell.run("settings put global tether_offload_disabled 1", 5);
    }

    private RootShell.Result restoreRootSystemState() {
        String forwarding = getPreferences().getString("previous_forwarding", "1");
        String offload = getPreferences().getString("previous_offload", "null");
        String restore = RootSharingPlan.cleanupScript()
            + ("0".equals(forwarding) ? "\nsysctl -w net.ipv4.ip_forward=0 >/dev/null" : "")
            + ((offload == null || offload.isBlank() || "null".equals(offload))
                ? "\nsettings delete global tether_offload_disabled >/dev/null"
                : "\nsettings put global tether_offload_disabled " + ("1".equals(offload) ? "1" : "0"));
        RootShell.Result result = RootShell.run(restore, 15);
        if (result.code() == 0) getPreferences().edit().clear().apply();
        return result;
    }

    private void failAndStopHotspot(String detail) {
        tethering.stop(worker, (ignored, stopDetail) -> finishOperation(false, detail));
    }

    private void finishOperation(boolean active, String detail) {
        main.post(() -> {
            busy.set(false);
            share.setText(active ? "Stop sharing" : "Start sharing");
            setBusy(false, null);
            message.setText(detail);
        });
    }

    private void setBusy(boolean value, String detail) {
        share.setEnabled(!value);
        share.setAlpha(value ? 0.65f : 1f);
        if (detail != null) message.setText(detail);
    }

    private android.content.SharedPreferences getPreferences() { return getSharedPreferences(PREFS, MODE_PRIVATE); }
    private static void sleep(long millis) { try { Thread.sleep(millis); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } }
    private static String concise(String value) { if (value == null || value.isBlank()) return "unknown error"; return value.length() > 180 ? value.substring(0, 180) + "…" : value; }

    private void showAbout() {
        new AlertDialog.Builder(this)
            .setTitle("VPN Share for Android")
            .setMessage("Version 0.1.0-alpha.2\n\nNavid Haghbayan (NH)\n09338140808\nTelegram: @nhaghbayan\nWebsite: sirgsm.ir\n\nRoot mode is experimental and must be tested on each phone/ROM. Android compatibility mode cannot promise that another app's VPN will be tethered.")
            .setPositiveButton("sirgsm.ir", (d, w) -> open("https://sirgsm.ir"))
            .setNegativeButton("Close", null).show();
    }

    private void open(String url) { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))); }
    private LinearLayout column(int gapIgnored) { LinearLayout value = new LinearLayout(this); value.setOrientation(LinearLayout.VERTICAL); return value; }
    private LinearLayout card() { LinearLayout value = column(0); value.setPadding(dp(20), dp(18), dp(20), dp(18)); value.setBackground(gradient(0x553d7185, 0x44325a78, 24)); value.setElevation(dp(2)); return value; }
    private LinearLayout.LayoutParams cardParams() { LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(-1, -2); p.setMargins(0, dp(18), 0, 0); return p; }
    private TextView text(String value, int sp, int color, int style) { TextView view = new TextView(this); view.setText(value); view.setTextSize(sp); view.setTextColor(color); view.setTypeface(Typeface.create("sans", style)); view.setLineSpacing(0, 1.12f); return view; }
    private Button button(String value, boolean primary) { Button view = new Button(this); view.setText(value); view.setAllCaps(false); view.setTextSize(primary ? 16 : 14); view.setTypeface(Typeface.DEFAULT, Typeface.BOLD); view.setTextColor(primary ? 0xff071d2d : Color.WHITE); view.setBackground(primary ? gradient(0xffd9fffb, 0xff69e8df, 30) : gradient(0x55355770, 0x44213b57, 22)); return view; }
    private View space(int height) { View value = new View(this); value.setLayoutParams(new LinearLayout.LayoutParams(1, dp(height))); return value; }
    private GradientDrawable gradient(int start, int end, int radius) { GradientDrawable value = new GradientDrawable(GradientDrawable.Orientation.TL_BR, new int[]{start, end}); value.setCornerRadius(dp(radius)); value.setStroke(dp(1), 0x556da6bd); return value; }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
}
