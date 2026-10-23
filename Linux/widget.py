#!/usr/bin/python3
"""Unprivileged GTK desktop widget; only the fixed helper runs through polkit."""
import json
import os
import secrets
import subprocess
import threading
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib
import core

CSS = b"""
window { background: transparent; color: #f1f7ff; font-family: 'Noto Sans', 'DejaVu Sans', sans-serif; }
.body { background: linear-gradient(125deg, rgba(24,66,80,.96), rgba(20,30,53,.97) 65%, rgba(44,39,71,.97)); border: 1px solid rgba(211,247,255,.48); border-radius: 30px; padding: 24px; }
.title { font-size: 25px; font-weight: 800; }
.overline { font-size: 9px; color: #aac3d6; }
.card { background: linear-gradient(120deg, rgba(198,242,255,.14), rgba(161,169,232,.08)); border: 1px solid rgba(220,244,255,.24); border-radius: 24px; padding: 17px; }
.vpn-state { color: #83efdb; font-size: 10px; font-weight: bold; }
.muted { color: #a8bed1; font-size: 11px; }
.warning { color: #ffce9e; font-size: 11px; }
.stat { font-size: 19px; font-weight: bold; }
entry, combobox button { background: rgba(190,224,255,.10); color: #f1f7ff; border: 1px solid rgba(216,243,255,.25); border-radius: 13px; box-shadow: none; padding: 10px; }
entry:focus { border-color: #83efdb; }
button { color: #eef8ff; background: linear-gradient(rgba(224,244,255,.14),rgba(200,219,255,.06)); border: 1px solid rgba(216,243,255,.22); border-radius: 19px; padding: 9px 15px; box-shadow: none; text-shadow: none; }
button:hover { background: rgba(225,247,255,.23); }
button.primary { color: #123444; font-weight: bold; font-size: 14px; background: linear-gradient(#dcfff8,#87e4df); border-radius: 26px; padding: 17px; border-color: #e3fffb; }
button:disabled { opacity: .45; }
menu { background: #22394d; color: #f1f7ff; }
checkbutton { color: #adc3d7; font-size: 11px; }
"""


def styled(widget, name):
    widget.get_style_context().add_class(name)
    return widget


def label(text, name="muted"):
    result = styled(Gtk.Label(label=text, xalign=0), name)
    result.set_line_wrap(True)
    return result


class Widget(Gtk.Window):
    def __init__(self):
        super().__init__(title="VPN Share")
        self.set_wmclass("vpnshare", "vpnshare")
        self.set_default_size(440, 700)
        self.set_resizable(False)
        self.set_decorated(False)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_app_paintable(True)
        visual = self.get_screen().get_rgba_visual()
        if visual: self.set_visual(visual)
        self.worker, self.busy, self.running, self.closing = None, False, False, False
        self.scanning, self.pinned, self.last_error = False, False, ""
        self.devices, self.log = {"vpns": [], "outputs": []}, []
        self.dns = ""
        self.box = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14), "body")
        self.add(self.box)
        header = Gtk.Box(spacing=8)
        titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        titles.pack_start(label("VPN Share", "title"), False, False, 0)
        titles.pack_start(label("A PRIVATE CONNECTION. SHARED.", "overline"), False, False, 0)
        header.pack_start(titles, True, True, 0)
        pin = Gtk.Button(label="◇")
        def keep_on_top(*_):
            self.pinned = not self.pinned
            self.set_keep_above(self.pinned)
            pin.set_label("◆" if self.pinned else "◇")
        pin.connect("clicked", keep_on_top)
        header.pack_start(pin, False, False, 0)
        close = Gtk.Button(label="×")
        close.connect("clicked", lambda *_: self.close())
        header.pack_start(close, False, False, 0)
        self.box.pack_start(header, False, False, 0)
        header.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
        header.connect("button-press-event", lambda _, event: self.begin_move_drag(event.button, int(event.x_root), int(event.y_root), event.time) if event.button == 1 else None)
        vpn = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12), "card")
        self.vpn_state = label("○  LOOKING FOR VPN", "vpn-state")
        self.vpn = Gtk.ComboBoxText()
        self.vpn.connect("changed", lambda *_: self.update_vpn())
        self.vpn_ip = label("Your connected VPN will appear here.")
        for item in (self.vpn_state, self.vpn, self.vpn_ip): vpn.pack_start(item, False, False, 0)
        self.box.pack_start(vpn, False, False, 0)
        output = styled(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10), "card")
        output.pack_start(label("Share through", "stat"), False, False, 0)
        self.output = Gtk.ComboBoxText()
        self.output.connect("changed", lambda *_: self.update_output())
        output.pack_start(self.output, False, False, 0)
        fields = Gtk.Box(spacing=10)
        self.ssid = Gtk.Entry(text="Navid VPN")
        self.ssid.set_max_length(32)
        self.ssid.set_width_chars(14)
        self.password = Gtk.Entry(text="VPN-" + secrets.token_hex(8))
        self.password.set_visibility(False)
        self.password.set_width_chars(14)
        self.password.set_max_length(63)
        for title, entry in (("NETWORK NAME", self.ssid), ("PASSWORD", self.password)):
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            column.pack_start(label(title, "overline"), False, False, 0)
            column.pack_start(entry, False, False, 0)
            fields.pack_start(column, True, True, 0)
        self.fields = fields
        output.pack_start(fields, False, False, 0)
        self.internet = label("USB / Ethernet / Wi-Fi internet")
        output.pack_start(self.internet, False, False, 0)
        self.box.pack_start(output, False, False, 0)
        self.toggle = styled(Gtk.Button(label="Start sharing"), "primary")
        self.toggle.connect("clicked", self.toggle_sharing)
        self.box.pack_start(self.toggle, False, False, 0)
        self.status = label("Scanning your connections…")
        self.box.pack_start(self.status, False, False, 0)
        stats = styled(Gtk.Box(spacing=20), "card")
        self.stats = []
        for title in ("CLIENTS", "UPLOAD", "DOWNLOAD"):
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
            column.pack_start(label(title, "overline"), False, False, 0)
            value = label("0" if title == "CLIENTS" else "0 B", "stat")
            self.stats.append(value)
            column.pack_start(value, False, False, 0)
            stats.pack_start(column, True, True, 0)
        self.box.pack_start(stats, False, False, 0)
        actions = Gtk.Box(spacing=8)
        for title, action in (("Options", self.options), ("Copy Wi-Fi", self.copy_wifi), ("Hide", lambda *_: self.iconify())):
            button = Gtk.Button(label=title)
            button.connect("clicked", action)
            actions.pack_start(button, True, True, 0)
        self.box.pack_start(actions, False, False, 0)
        footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        footer.pack_start(label("0.5.0 Preview", "overline"), True, True, 0)
        about = Gtk.Button(label="About")
        about.connect("clicked", self.about)
        footer.pack_start(about, False, False, 0)
        footer.pack_end(label("NH", "overline"), False, False, 0)
        footer.pack_end(Gtk.LinkButton.new_with_label("https://sirgsm.ir", "sirgsm.ir"), False, False, 0)
        self.box.pack_start(footer, False, False, 0)
        self.connect("delete-event", self.on_close)
        GLib.timeout_add_seconds(5, self.refresh)
        self.refresh()

    def message(self, text):
        self.status.set_text(text)
        self.log.append(text)
        self.log = self.log[-100:]

    def refresh(self):
        if self.running or self.busy or self.scanning: return True
        self.scanning = True
        def scan():
            try:
                devices = core.inventory()
                GLib.idle_add(self.scanned, devices, None)
            except Exception as error:
                GLib.idle_add(self.scanned, None, str(error))
        threading.Thread(target=scan, daemon=True).start()
        return True

    def scanned(self, devices, error):
        self.scanning = False
        if self.busy or self.running: return False
        if error:
            self.message(error); return False
        selected, output = self.vpn.get_active_id(), self.output.get_active_id()
        self.devices = devices
        self.vpn.remove_all(); self.output.remove_all()
        for item in devices["vpns"]: self.vpn.append(item["name"], item["title"])
        for item in devices["outputs"]: self.output.append(item["name"], ("Wi-Fi hotspot" if item["kind"] == "wifi" else "Ethernet") + " · " + item["name"])
        if not selected or not self.vpn.set_active_id(selected): self.vpn.set_active(0)
        if not output or not self.output.set_active_id(output): self.output.set_active(0)
        self.internet.set_text("Internet via " + devices["input"])
        self.message("Ready. Choose an output and start sharing." if devices["vpns"] else "Connect a routed VPN; it will appear automatically.")
        return False

    def update_vpn(self):
        item = next((item for item in self.devices["vpns"] if item["name"] == self.vpn.get_active_id()), None)
        self.vpn_state.set_text("●  VPN DETECTED" if item else "○  WAITING FOR VPN")
        self.vpn_ip.set_text((item["ip"] + "  ·  " + item["name"]) if item else "Connect your VPN to begin.")

    def update_output(self):
        item = next((item for item in self.devices["outputs"] if item["name"] == self.output.get_active_id()), None)
        self.fields.set_sensitive(not item or item["kind"] == "wifi")

    def controls(self):
        self.toggle.set_sensitive(not self.busy)
        for item in (self.vpn, self.output, self.ssid, self.password): item.set_sensitive(not self.busy and not self.running)
        self.toggle.set_label("Please wait…" if self.busy else "Stop sharing" if self.running else "Start sharing")

    def toggle_sharing(self, *_):
        if self.busy: return
        if self.running:
            self.worker.stdin.write(json.dumps({"action": "stop"}) + "\n"); self.worker.stdin.flush()
            self.busy = True; self.controls(); return
        item = next((item for item in self.devices["outputs"] if item["name"] == self.output.get_active_id()), None)
        if not self.vpn.get_active_id() or not item:
            self.message("Connect a VPN and choose an available output adapter."); return
        request = {"action": "start", "vpn": self.vpn.get_active_id(), "output": item["name"], "mode": item["kind"],
                   "ssid": self.ssid.get_text(), "password": self.password.get_text(), "dns": self.dns}
        try:
            core.validate_request(request)
            self.last_error = ""
            self.busy = True; self.controls(); self.message("Preparing the connection. Administrator authentication may appear.")
            self.worker = subprocess.Popen(["/usr/bin/pkexec", "/usr/lib/vpnshare/vpnshare-helper"], stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            self.worker.stdin.write(json.dumps(request) + "\n"); self.worker.stdin.flush()
            threading.Thread(target=self.read_worker, daemon=True).start()
        except Exception as error:
            self.busy = False; self.controls(); self.message(str(error))

    def read_worker(self):
        try:
            for line in self.worker.stdout:
                GLib.idle_add(self.event, json.loads(line))
            error = self.worker.stderr.read()
            self.worker.wait()
            GLib.idle_add(self.worker_finished, error)
        except Exception as error:
            GLib.idle_add(self.worker_finished, str(error))

    def event(self, event):
        if event["event"] == "started":
            self.running, self.busy = True, False
            self.message("Sharing configured. Connect a device to your network.")
        elif event["event"] == "stopped":
            self.running, self.busy = False, False
            self.message(self.last_error or "Sharing stopped. Previous settings restored.")
        elif event["event"] == "error":
            self.last_error = event["error"]
            self.message(event["error"])
        elif event["event"] == "status":
            self.vpn_state.set_text("●  SHARING VIA VPN" if event["connected"] else "●  WAITING FOR VPN")
            self.message("Sharing via VPN." if event["connected"] else "VPN interrupted. Client internet is paused.")
            self.stats[0].set_text(str(len(event["clients"])))
            for widget, key in zip(self.stats[1:], ("upload", "download")): widget.set_text(self.bytes(event[key]))
            if event.get("error"): self.log.append(event["error"])
        self.controls()
        return False

    def worker_finished(self, error):
        self.worker = None; self.running, self.busy = False, False; self.controls()
        if error: self.message(error.strip()[-350:])
        if self.closing: Gtk.main_quit()
        return False

    @staticmethod
    def bytes(value):
        for suffix in ("B", "KB", "MB", "GB"):
            if value < 1024: return f"{value:.0f} {suffix}" if suffix == "B" else f"{value:.1f} {suffix}"
            value /= 1024
        return f"{value:.1f} TB"

    def copy_wifi(self, *_):
        Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(f"Network: {self.ssid.get_text()}\nPassword: {self.password.get_text()}", -1)
        self.message("Wi-Fi details copied.")

    def options(self, *_):
        dialog = Gtk.Dialog(title="VPN Share options", transient_for=self, modal=True)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        box = dialog.get_content_area(); box.set_spacing(12); box.set_border_width(20)
        box.pack_start(Gtk.Label(label="DNS resolver (empty = 1.1.1.1 through the VPN)"), False, False, 0)
        dns = Gtk.Entry(text=self.dns); dns.set_sensitive(not self.running); box.pack_start(dns, False, False, 0)
        reveal = Gtk.CheckButton(label="Show Wi-Fi password"); reveal.set_active(self.password.get_visibility()); reveal.connect("toggled", lambda item: self.password.set_visibility(item.get_active())); box.pack_start(reveal, False, False, 0)
        activity = Gtk.TextView(); activity.set_editable(False); activity.set_size_request(430, 200); activity.get_buffer().set_text("\n".join(self.log[-20:])); box.pack_start(activity, True, True, 0)
        dialog.show_all(); dialog.run()
        if not self.running: self.dns = dns.get_text().strip()
        dialog.destroy()

    def about(self, *_):
        with open(os.path.join(os.path.dirname(__file__), "about.json"), encoding="utf-8") as source:
            info = json.load(source)
        dialog = Gtk.Dialog(title="About VPN Share", transient_for=self, modal=True)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        box = dialog.get_content_area(); box.set_spacing(14); box.set_border_width(24)
        for text in ("VPN Share", info["version"] + " · Preview", info["author"], "Phone: " + info["phone"]):
            box.pack_start(Gtk.Label(label=text), False, False, 0)
        box.pack_start(Gtk.LinkButton.new_with_label("https://t.me/" + info["telegram"], "Telegram: @" + info["telegram"]), False, False, 0)
        box.pack_start(Gtk.LinkButton.new_with_label(info["website"], "sirgsm.ir"), False, False, 0)
        note = Gtk.Label(label="Personal-use preview. Linux hardware, VPN disconnect, leak and crash-recovery acceptance tests are pending.")
        note.set_line_wrap(True); note.set_max_width_chars(48); box.pack_start(note, False, False, 0)
        dialog.show_all(); dialog.run(); dialog.destroy()

    def on_close(self, *_):
        if self.worker:
            self.closing = True
            try:
                self.worker.stdin.write(json.dumps({"action": "stop"}) + "\n"); self.worker.stdin.flush()
            except (OSError, BrokenPipeError): self.worker.stdin.close()
            self.message("Restoring network settings before closing…")
            return True
        Gtk.main_quit()
        return False


if __name__ == "__main__":
    provider = Gtk.CssProvider(); provider.load_from_data(CSS)
    Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    app = Widget(); app.show_all(); Gtk.main()
