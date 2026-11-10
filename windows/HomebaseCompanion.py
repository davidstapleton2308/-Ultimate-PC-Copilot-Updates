"""Homebase Companion 1.1 — private Windows LAN control bridge."""
import base64
import ctypes
import datetime
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import threading
import time
import tkinter as tk
from tkinter import ttk
import webbrowser

import psutil
import qrcode
from PIL import ImageTk
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PORT = 47655
STORE = Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "Homebase"
STORE.mkdir(parents=True, exist_ok=True)
SETTINGS = STORE / "devices.json"
CERT = STORE / "homebase-cert.pem"
KEY = STORE / "homebase-key.pem"
state_lock = threading.RLock()
state = {"pair": "", "pair_ends": 0.0, "devices": [], "failures": {}}
status_note = "Starting..."
server = None


def load_state():
    if SETTINGS.exists():
        try:
            obj = json.loads(SETTINGS.read_text("utf-8"))
            if isinstance(obj.get("devices"), list):
                state["devices"] = obj["devices"][:12]
        except (OSError, ValueError, TypeError):
            pass


def save_state():
    tmp = SETTINGS.with_suffix(".tmp")
    tmp.write_text(json.dumps({"devices": state["devices"]}, indent=2), "utf-8")
    tmp.replace(SETTINGS)


def rotate_pair():
    with state_lock:
        state["pair"] = f"{secrets.randbelow(1000000):06d}"
        state["pair_ends"] = time.time() + 300
        state["failures"] = {}
        return state["pair"]


def ensure_certificate():
    if CERT.exists() and KEY.exists():
        try:
            x509.load_pem_x509_certificate(CERT.read_bytes())
            return
        except Exception:
            pass
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Homebase Local Companion"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Homebase Personal"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private, hashes.SHA256()))
    KEY.write_bytes(private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def fingerprint():
    cert = x509.load_pem_x509_certificate(CERT.read_bytes())
    return cert.fingerprint(hashes.SHA256()).hex()


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            value = s.getsockname()[0]
            if ipaddress.ip_address(value).is_private:
                return value
        finally:
            s.close()
    except OSError:
        pass
    for ifname, addresses in psutil.net_if_addrs().items():
        if any(word in ifname.lower() for word in ("virtual", "vbox", "hyper-v", "loopback", "vmware")):
            continue
        for address in addresses:
            if address.family == socket.AF_INET and not address.address.startswith("127."):
                if ipaddress.ip_address(address.address).is_private:
                    return address.address
    return "127.0.0.1"


def nearby(ip):
    try:
        value = ipaddress.ip_address(ip)
        return value.version == 4 and (value.is_private or value.is_loopback)
    except ValueError:
        return False


def installed_apps():
    candidates = [
        Path(os.getenv("LOCALAPPDATA", "")) / "Playnite" / "Playnite.DesktopApp.exe",
        Path(os.getenv("PROGRAMFILES", "")) / "Playnite" / "Playnite.DesktopApp.exe",
        Path(os.getenv("PROGRAMFILES(X86)", "")) / "Steam" / "steam.exe",
        Path(os.getenv("PROGRAMFILES", "")) / "Steam" / "steam.exe",
    ]
    playnite = next((str(p) for p in candidates[:2] if p.is_file()), "")
    steam = next((str(p) for p in candidates[2:] if p.is_file()), "")
    try:
        import winreg
        for root, name in ((winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam"),
                           (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam")):
            try:
                with winreg.OpenKey(root, name) as key:
                    rootpath, _ = winreg.QueryValueEx(key, "SteamPath")
                    exe = Path(rootpath) / "steam.exe"
                    if exe.is_file():
                        steam = str(exe)
                        break
            except OSError:
                pass
    except ImportError:
        pass
    return {"playnite": playnite, "steam": steam}


def status():
    battery = psutil.sensors_battery()
    apps = installed_apps()
    return {
        "name": socket.gethostname(),
        "platform": "Windows",
        "online": True,
        "cpu": round(psutil.cpu_percent(interval=None)),
        "memory": round(psutil.virtual_memory().percent),
        "battery": round(battery.percent) if battery else None,
        "charging": bool(battery.power_plugged) if battery else None,
        "playnite": bool(apps["playnite"]),
        "steam": bool(apps["steam"]),
        "version": "1.1",
    }


def media_key(vk):
    user32 = ctypes.windll.user32
    user32.keybd_event(vk, 0, 0, 0)
    user32.keybd_event(vk, 0, 2, 0)


def perform_action(action):
    if action == "volume_up":
        media_key(0xAF)
    elif action == "volume_down":
        media_key(0xAE)
    elif action == "mute":
        media_key(0xAD)
    elif action == "lock":
        if ctypes.windll.user32.LockWorkStation() == 0:
            raise RuntimeError("Windows could not lock")
    elif action in ("playnite", "steam"):
        exe = installed_apps()[action]
        if not exe:
            raise RuntimeError(action.title() + " is not installed at a recognized location")
        os.startfile(exe)
    elif action == "sleep":
        if ctypes.windll.powrprof.SetSuspendState(False, False, False) == 0:
            raise RuntimeError("Windows refused to sleep")
    else:
        raise ValueError("Unsupported control")


class API(http.server.BaseHTTPRequestHandler):
    server_version = "HomebaseCompanion/1.1"
    def log_message(self, fmt, *args):
        return

    def reply(self, code, content):
        raw = json.dumps(content, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def parse_body(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 2048:
                return None
            obj = json.loads(self.rfile.read(size).decode("utf-8"))
            return obj if isinstance(obj, dict) else None
        except (OSError, ValueError, UnicodeError):
            return None

    def authorized(self):
        supplied = self.headers.get("X-Homebase-Token", "")
        if not supplied or len(supplied) > 128:
            return False
        token_hash = hashlib.sha256(supplied.encode("ascii", "ignore")).hexdigest()
        with state_lock:
            return any(hmac.compare_digest(token_hash, d.get("hash", "")) for d in state["devices"])

    def permitted(self):
        if not nearby(self.client_address[0]):
            self.reply(403, {"error": "Local network only"})
            return False
        return True

    def do_GET(self):
        if not self.permitted():
            return
        if self.path == "/status" and self.authorized():
            self.reply(200, status())
        else:
            self.reply(401, {"error": "Pair this phone with the companion"})

    def do_POST(self):
        if not self.permitted():
            return
        body = self.parse_body()
        if body is None:
            self.reply(400, {"error": "Invalid request"})
            return
        if self.path == "/pair":
            proposed = str(body.get("code", ""))
            with state_lock:
                ip = self.client_address[0]
                rec = state["failures"].get(ip, {"count": 0, "blocked": 0})
                now = time.time()
                if rec["blocked"] > now:
                    self.reply(429, {"error": "Too many attempts. Try later."})
                    return
                if now >= state["pair_ends"] or not hmac.compare_digest(state["pair"], proposed):
                    rec["count"] += 1
                    if rec["count"] >= 5:
                        rec["blocked"] = now + 300
                        rec["count"] = 0
                    state["failures"][ip] = rec
                    self.reply(403, {"error": "Invalid or expired pairing code"})
                    return
                if len(state["devices"]) >= 12:
                    self.reply(403, {"error": "Device limit reached"})
                    return
                token = secrets.token_urlsafe(32)
                state["devices"].append({"hash": hashlib.sha256(token.encode()).hexdigest(),
                                         "created": int(now)})
                save_state()
                rotate_pair()
            self.reply(200, {"token": token, "name": socket.gethostname()})
        elif self.path == "/command":
            if not self.authorized():
                self.reply(401, {"error": "Unauthorized"})
                return
            command = str(body.get("action", ""))
            if command not in {"volume_up", "volume_down", "mute", "lock",
                               "sleep", "playnite", "steam"}:
                self.reply(400, {"error": "Unsupported action"})
                return
            # Respond before putting the machine to sleep or locking its screen.
            if command in ("sleep", "lock"):
                self.reply(200, {"ok": True, "action": command})
                threading.Timer(0.8, lambda: perform_action(command)).start()
                return
            try:
                perform_action(command)
                self.reply(200, {"ok": True, "action": command})
            except Exception as exc:
                self.reply(400, {"error": str(exc)})
        else:
            self.reply(404, {"error": "Not found"})


class Window(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Homebase Companion")
        self.geometry("430x650")
        self.minsize(400, 590)
        self.configure(bg="#07120c")
        self.resizable(False, False)
        self.ip = local_ip()
        self.fp = fingerprint()
        self.image = None
        self.pairing_data = ""
        self.code = rotate_pair()
        self.make_ui()
        self.update_pairing()
        self.after(5000, self.tick)

    def make_ui(self):
        fg, bg, mute, green = "#eaf8ec", "#07120c", "#9db5a5", "#73dfa1"
        tk.Label(self, text="⌂  HOMEBASE", font=("Segoe UI", 22, "bold"),
                 fg=green, bg=bg).pack(pady=(24, 4))
        tk.Label(self, text="Secure Windows Companion", font=("Segoe UI", 11),
                 fg=mute, bg=bg).pack()
        self.status_label = tk.Label(self, text="Secure local server starting...",
                                     fg=green, bg=bg, font=("Segoe UI", 10))
        self.status_label.pack(pady=(18, 5))
        self.qr = tk.Label(self, bg="white", bd=10, relief="flat")
        self.qr.pack(pady=12)
        tk.Label(self, text="Scan this QR code from Homebase > Laptop",
                 fg=fg, bg=bg, font=("Segoe UI", 10, "bold")).pack(pady=(6, 4))
        self.pin_label = tk.Label(self, text="", fg=green, bg=bg,
                                  font=("Consolas", 18, "bold"))
        self.pin_label.pack()
        self.ip_label = tk.Label(self, text="", fg=mute, bg=bg, font=("Segoe UI", 10))
        self.ip_label.pack(pady=(8, 2))
        self.expire_label = tk.Label(self, text="", fg=mute, bg=bg,
                                     font=("Segoe UI", 9))
        self.expire_label.pack()
        tk.Button(self, text="Refresh pairing QR", command=self.update_pairing,
                  bg="#1a4d2c", fg="white", activebackground="#2c7043",
                  font=("Segoe UI", 10), relief="flat", padx=18, pady=9).pack(pady=12)
        tk.Button(self, text="Copy pairing data", command=self.copy_pair_data,
                  bg="#15241b", fg="#73dfa1", relief="flat", padx=18, pady=8).pack(pady=(0, 6))
        tk.Label(self, text="Phone and laptop must be on the same Wi-Fi.\n"
                           "Allow Homebase on Private networks in Windows Firewall.\n"
                           "Never forward port 47655 to the internet.",
                 fg=mute, bg=bg, justify="center",
                 font=("Segoe UI", 9)).pack(pady=8)

    def update_pairing(self):
        self.code = rotate_pair()
        value = json.dumps({"v": 1, "ip": self.ip, "port": PORT,
                            "fp": self.fp, "code": self.code}, separators=(",", ":"))
        self.pairing_data = value
        graphic = qrcode.QRCode(border=2, box_size=5, error_correction=qrcode.constants.ERROR_CORRECT_M)
        graphic.add_data(value)
        graphic.make(fit=True)
        raw = graphic.make_image(fill_color="black", back_color="white").convert("RGB")
        self.image = ImageTk.PhotoImage(raw)
        self.qr.configure(image=self.image)
        self.pin_label.configure(text="Pairing PIN: " + self.code)
        self.ip_label.configure(text="Laptop address: " + self.ip + ":" + str(PORT))
        self.expire_label.configure(text="QR expires in 5 minutes")

    def copy_pair_data(self):
        self.clipboard_clear()
        self.clipboard_append(self.pairing_data)
        self.update()

    def tick(self):
        remaining = int(state["pair_ends"] - time.time())
        if remaining < 1:
            self.update_pairing()
        else:
            self.expire_label.configure(text="Pairing code refreshes in " + str(remaining) + "s")
        self.after(5000, self.tick)


def start_api(window):
    global server
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(CERT), str(KEY))
        server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), API)
        server.daemon_threads = True
        server.socket = context.wrap_socket(server.socket, server_side=True)
        window.after(0, lambda: window.status_label.configure(text="● Online • encrypted local connection"))
        server.serve_forever(poll_interval=0.5)
    except Exception as exc:
        text = "Server error: " + str(exc)
        window.after(0, lambda: window.status_label.configure(text=text, fg="#ffbb88"))


def main():
    load_state()
    ensure_certificate()
    window = Window()
    threading.Thread(target=start_api, args=(window,), daemon=True).start()
    window.mainloop()
    if server:
        server.shutdown()


if __name__ == "__main__":
    main()
