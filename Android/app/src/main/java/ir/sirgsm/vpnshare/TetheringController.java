package ir.sirgsm.vpnshare;

import android.content.Context;
import android.content.Intent;
import android.net.TetheringManager;
import android.os.Build;
import android.provider.Settings;

import java.util.concurrent.Executor;

public final class TetheringController {
    public interface Callback { void complete(boolean started, String message); }

    private final Context context;
    private TetheringManager.TetheringRequest request;

    public TetheringController(Context context) { this.context = context; }

    public boolean canStartDirectly() { return Build.VERSION.SDK_INT >= 36; }

    public void start(Executor executor, Callback callback) {
        if (Build.VERSION.SDK_INT < 36) {
            callback.complete(false, "Android 15 or older requires the system hotspot panel.");
            return;
        }
        try {
            TetheringManager manager = context.getSystemService(TetheringManager.class);
            if (manager == null) {
                callback.complete(false, "Tethering service is unavailable.");
                return;
            }
            request = new TetheringManager.TetheringRequest.Builder(TetheringManager.TETHERING_WIFI).build();
            manager.startTethering(request, executor, new TetheringManager.StartTetheringCallback() {
                @Override public void onTetheringStarted() { callback.complete(true, "Wi-Fi hotspot started."); }
                @Override public void onTetheringFailed(int error) { callback.complete(false, "Android rejected hotspot start (error " + error + ")."); }
            });
        } catch (SecurityException error) {
            callback.complete(false, "This device does not grant tethering control to third-party apps.");
        } catch (RuntimeException error) {
            callback.complete(false, "Hotspot start failed: " + error.getClass().getSimpleName());
        }
    }

    public void stop(Executor executor, Callback callback) {
        if (Build.VERSION.SDK_INT < 36 || request == null) {
            callback.complete(true, "No app-owned hotspot request is active.");
            return;
        }
        TetheringManager manager = context.getSystemService(TetheringManager.class);
        if (manager == null) {
            callback.complete(false, "Tethering service is unavailable.");
            return;
        }
        try {
            manager.stopTethering(request, executor, new TetheringManager.StopTetheringCallback() {
                @Override public void onStopTetheringSucceeded() { request = null; callback.complete(true, "Hotspot stopped."); }
                @Override public void onStopTetheringFailed(int error) { callback.complete(false, "Hotspot stop failed (error " + error + ")."); }
            });
        } catch (SecurityException error) {
            callback.complete(false, "Android denied hotspot stop.");
        }
    }

    public void openSettings() {
        Intent intent = new Intent("android.settings.TETHER_SETTINGS").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        context.startActivity(intent);
    }
}
