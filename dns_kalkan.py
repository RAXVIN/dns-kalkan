"""
DNS Kalkan v2  -  (c) 2026 Wesar

Discord ve seçtiğin engelli siteler için kişisel, hafif erişim aracı (Windows 10/11).

Nasıl çalışır (yönetici izni GEREKMEZ, sistem DNS ayarlarına dokunmaz):
  1. Şifreli DNS (DoH): Listedeki sitelerin adresleri ISS'nin sahte DNS'i yerine
     Cloudflare/Google/... üzerinden HTTPS ile çözülür.
  2. SNI bölme: Bağlantının ilk TLS paketi (ClientHello) site adının ortasından
     ikiye bölünür; operatörün DPI cihazı site adını okuyamaz.
  3. PAC: Windows'a yalnızca listedeki siteleri 127.0.0.1:8881'e yönlendiren bir
     otomatik proxy dosyası tanıtılır. Oyunlar ve diğer her şey doğrudan gider.
  4. Discord masaüstü, tünel ayarlarıyla (HTTPS_PROXY + --proxy-server) başlatılır.

Kullanım:
  pythonw dns_kalkan.py            -> arayüz
  python  dns_kalkan.py --restore  -> proxy ayarlarını geri yükle (kurtarma)
"""
from __future__ import annotations

import ctypes
import http.client
import json
import math
import os
import queue
import random
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from urllib.parse import urlsplit

APP_NAME = "DNS Kalkan"
VERSION = "2.1"
AUTHOR = "Wesar"

APP_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "DNSKalkan")
CONFIG_PATH = os.path.join(APP_DIR, "ayarlar.json")
BACKUP_PATH = os.path.join(APP_DIR, "dns_yedek.json")
LOG_PATH = os.path.join(APP_DIR, "kayit.txt")

PROXY_PORT = 8881
PROXY_URL = f"http://127.0.0.1:{PROXY_PORT}"
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
SSL_CTX = ssl.create_default_context()

PROVIDERS = {
    "Cloudflare": {"doh": "https://1.1.1.1/dns-query", "ip": "1.1.1.1"},
    "Google": {"doh": "https://8.8.8.8/dns-query", "ip": "8.8.8.8"},
    "AdGuard": {"doh": "https://94.140.14.14/dns-query", "ip": "94.140.14.14"},
    "OpenDNS": {"doh": "https://208.67.222.222/dns-query", "ip": "208.67.222.222"},
    "Özel sunucu": None,
}

DISCORD_PROFILE = [
    "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
    "discord.media", "discordcdn.com", "discord.dev", "discord.new",
    "discord.gift", "discord.co", "discordstatus.com", "dis.gd",
]

DEFAULT_CONFIG = {
    "provider": "Cloudflare",
    "custom": "",
    "domains": list(DISCORD_PROFILE),
    "launch_discord": True,
}

BENIGN = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError, socket.timeout,
          socket.gaierror)


# ===================================================================== kayıt
_listeners: list = []


def ensure_dir():
    os.makedirs(APP_DIR, exist_ok=True)


def file_log(msg: str):
    try:
        ensure_dir()
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    except Exception:
        pass


def log(msg: str):
    file_log(msg)
    line = time.strftime("%H:%M:%S  ") + msg
    for fn in list(_listeners):
        try:
            fn(line)
        except Exception:
            pass


def install_crash_logging():
    ensure_dir()
    if sys.stderr is None or sys.stdout is None:  # pythonw
        f = open(LOG_PATH, "a", encoding="utf-8", buffering=1)
        sys.stderr = sys.stdout = f
    sys.excepthook = lambda t, v, tb: file_log("HATA:\n" + "".join(traceback.format_exception(t, v, tb)))
    threading.excepthook = lambda a: file_log(
        "THREAD HATASI:\n" + "".join(traceback.format_exception(a.exc_type, a.exc_value, a.exc_traceback)))


# ===================================================================== ayarlar
def load_config() -> dict:
    ensure_dir()
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg = {**DEFAULT_CONFIG, **json.load(f)}
    except Exception:
        cfg = dict(DEFAULT_CONFIG, domains=list(DISCORD_PROFILE))
    if cfg.get("provider") not in PROVIDERS:  # eski sürümden kalan ad
        old = str(cfg.get("provider", ""))
        cfg["provider"] = next((k for k in PROVIDERS if old.startswith(k)), "Cloudflare")
    return cfg


def save_config(cfg: dict):
    ensure_dir()
    keep = {k: cfg[k] for k in DEFAULT_CONFIG}
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(keep, f, ensure_ascii=False, indent=2)


def provider_of(cfg: dict) -> dict:
    p = PROVIDERS.get(cfg.get("provider"))
    if p:
        return {"doh": p["doh"], "udp": None, "ip": p["ip"], "name": cfg["provider"]}
    custom = (cfg.get("custom") or "").strip()
    if custom.lower().startswith("https://"):
        return {"doh": custom, "udp": None, "ip": None, "name": custom}
    if custom:
        host, port = custom, 53
        if custom.count(":") == 1:
            host, p_ = custom.split(":")
            port = int(p_)
        return {"doh": None, "udp": (host, port), "ip": host, "name": custom}
    raise ValueError("Özel sunucu seçili ama adres girilmemiş.")


# ===================================================================== DNS paketleri
def build_query(name: str, qtype: int = 1) -> bytes:
    q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    for part in name.strip(".").split("."):
        q += bytes([len(part)]) + part.encode("idna")
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


def _skip_name(p: bytes, i: int) -> int:
    while True:
        ln = p[i]
        if ln == 0:
            return i + 1
        if ln & 0xC0:
            return i + 2
        i += 1 + ln


def parse_records(resp: bytes, rtype_want: int) -> list[str]:
    try:
        qd, an = struct.unpack(">HH", resp[4:8])
        i = 12
        for _ in range(qd):
            i = _skip_name(resp, i) + 4
        out = []
        for _ in range(an):
            i = _skip_name(resp, i)
            rtype, _, _, rdlen = struct.unpack(">HHIH", resp[i:i + 10])
            i += 10
            if rtype == rtype_want == 1 and rdlen == 4:
                out.append(socket.inet_ntoa(resp[i:i + 4]))
            elif rtype == rtype_want == 28 and rdlen == 16:
                out.append(socket.inet_ntop(socket.AF_INET6, resp[i:i + 16]))
            i += rdlen
        return out
    except Exception:
        return []


def udp_query(server: tuple, q: bytes, timeout: float = 3.0) -> bytes:
    fam = socket.AF_INET6 if ":" in server[0] else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, server)
        end = time.time() + timeout
        while time.time() < end:
            data, _ = s.recvfrom(65535)
            if data[:2] == q[:2]:
                return data
    raise TimeoutError("DNS yanıtı yok")


class DohClient:
    """Bağlantıyı yeniden kullanan DNS-over-HTTPS istemcisi (RFC 8484)."""

    def __init__(self, url: str):
        u = urlsplit(url)
        self.host, self.port, self.path = u.hostname, u.port or 443, u.path or "/dns-query"
        self._idle: list = []
        self._lock = threading.Lock()

    def query(self, q: bytes) -> bytes:
        body = b"\x00\x00" + q[2:]
        err = None
        for _ in range(2):
            with self._lock:
                conn = self._idle.pop() if self._idle else None
            if conn is None:
                conn = http.client.HTTPSConnection(self.host, self.port, timeout=5, context=SSL_CTX)
            try:
                conn.request("POST", self.path, body=body, headers={
                    "content-type": "application/dns-message", "accept": "application/dns-message"})
                r = conn.getresponse()
                data = r.read()
                if r.status != 200:
                    raise IOError(f"HTTP {r.status}")
                with self._lock:
                    if len(self._idle) < 8:
                        self._idle.append(conn)
                return q[:2] + data[2:]
            except Exception as e:
                err = e
                conn.close()
        raise err


class Resolver:
    """Site adlarını seçilen sağlayıcıdan (DoH) çözer; ISS DNS'ine hiç sormaz."""

    def __init__(self, cfg: dict):
        self.prov = provider_of(cfg)
        self.doh = DohClient(self.prov["doh"]) if self.prov["doh"] else None
        self.cache: dict = {}
        self.lock = threading.Lock()
        self.queries = 0
        self.last_ms: float | None = None
        self.ok = True

    def _ask(self, host: str, qtype: int) -> list[str]:
        q = build_query(host, qtype)
        if self.doh:
            try:
                return parse_records(self.doh.query(q), qtype)
            except Exception:
                if not self.prov["ip"]:
                    raise
        srv = self.prov["udp"] or (self.prov["ip"], 53)
        return parse_records(udp_query(srv, q), qtype)

    def lookup_strict(self, host: str) -> list[str]:
        t = time.perf_counter()
        try:
            ips = self._ask(host, 1) or self._ask(host, 28)
            self.ok = True
        except Exception:
            self.ok = False
            raise
        finally:
            self.last_ms = (time.perf_counter() - t) * 1000
            self.queries += 1
        if not ips:
            raise IOError(f"{host} için adres yok")
        return ips

    def lookup(self, host: str) -> str:
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
            return host
        except OSError:
            pass
        now = time.time()
        with self.lock:
            hit = self.cache.get(host)
            if hit and hit[1] > now:
                return random.choice(hit[0])
        try:
            ips = self.lookup_strict(host)
        except Exception:
            ips = [ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)]  # son çare
        with self.lock:
            if len(self.cache) > 2000:
                self.cache.clear()
            self.cache[host] = (ips, now + 300)
        return random.choice(ips)


# ===================================================================== SNI bölücü proxy
def fragment_client_hello(record: bytes, host: str) -> list[bytes]:
    """TLS ClientHello kaydını site adının ortasından iki TLS kaydına böler."""
    if len(record) < 6 or record[0] != 0x16:
        return [record]
    head, payload = record[:3], record[5:]
    idx = payload.find(host.encode()) if host else -1
    split = idx + max(1, len(host) // 2) if idx > 0 else 2
    parts = [payload[:split], payload[split:]]
    recs = [head + len(p).to_bytes(2, "big") + p for p in parts]
    return [recs[0][:1], recs[0][1:], recs[1]]


class DpiProxy:
    def __init__(self, resolver: Resolver, domains: list[str], port: int = PROXY_PORT):
        self.resolver = resolver
        self.domains = list(domains)
        self.port = port
        self.sock: socket.socket | None = None
        self.total = 0
        self.active = 0
        self._lock = threading.Lock()

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", self.port))
        except OSError:
            s.close()
            raise RuntimeError(f"{self.port} portu kullanımda. {APP_NAME} zaten açık olabilir; "
                               "görev çubuğunu ve sistem tepsisini kontrol et.")
        s.listen(256)
        self.sock = s
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        s, self.sock = self.sock, None
        if s:
            try:
                s.close()
            except Exception:
                pass

    def pac(self) -> bytes:
        doms = json.dumps([d.lower() for d in self.domains])
        return (
            "function FindProxyForURL(url, host) {\n"
            "  host = host.toLowerCase();\n"
            f"  var d = {doms};\n"
            "  for (var i = 0; i < d.length; i++)\n"
            "    if (host == d[i] || dnsDomainIs(host, '.' + d[i]))\n"
            f"      return 'PROXY 127.0.0.1:{self.port}; DIRECT';\n"
            "  return 'DIRECT';\n}\n").encode()

    def _accept(self):
        while self.sock:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c: socket.socket):
        up = None
        host = "?"
        with self._lock:
            self.active += 1
        try:
            c.settimeout(20)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = c.recv(8192)
                if not chunk or len(buf) > 65536:
                    return
                buf += chunk
            head, rest = buf.split(b"\r\n\r\n", 1)
            first = head.split(b"\r\n", 1)[0].decode("latin-1")
            method, target, _ = first.split(" ", 2)

            if method == "GET" and target.startswith("/proxy.pac"):
                body = self.pac()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n"
                          b"Cache-Control: no-store\r\nContent-Length: " + str(len(body)).encode() +
                          b"\r\nConnection: close\r\n\r\n" + body)
                return

            with self._lock:
                self.total += 1
            if method.upper() == "CONNECT":
                h, _, port = target.rpartition(":")
                host = h.strip("[]").lower()
                up = socket.create_connection((self.resolver.lookup(host), int(port)), timeout=10)
                up.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                data = rest or c.recv(16384)
                while len(data) >= 5 and data[0] == 0x16 and len(data) < 5 + int.from_bytes(data[3:5], "big"):
                    more = c.recv(16384)
                    if not more:
                        break
                    data += more
                if data[:1] == b"\x16" and len(data) >= 5:
                    n = 5 + int.from_bytes(data[3:5], "big")
                    for piece in fragment_client_hello(data[:n], host):
                        up.sendall(piece)
                        time.sleep(0.005)
                    if data[n:]:
                        up.sendall(data[n:])
                elif data:
                    up.sendall(data)
            else:
                u = urlsplit(target)
                host = (u.hostname or "?").lower()
                up = socket.create_connection((self.resolver.lookup(host), u.port or 80), timeout=10)
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                up.sendall(f"{method} {path} HTTP/1.1".encode() + head[len(first):] + b"\r\n\r\n" + rest)
            self._relay(c, up)
        except BENIGN:
            pass
        except Exception as e:
            log(f"Bağlantı hatası ({host}): {type(e).__name__}: {e}")
        finally:
            with self._lock:
                self.active -= 1
            for s in (c, up):
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

    @staticmethod
    def _relay(a: socket.socket, b: socket.socket):
        a.settimeout(None)
        b.settimeout(None)
        while True:
            r, _, x = select.select([a, b], [], [a, b], 600)
            if x or not r:
                return
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)


# ===================================================================== Windows proxy (PAC)
INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
PROXY_VALUES = ("AutoConfigURL", "ProxyEnable", "ProxyServer", "ProxyOverride")


def read_proxy_settings() -> dict:
    import winreg
    out = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY) as k:
        for name in PROXY_VALUES:
            try:
                val, typ = winreg.QueryValueEx(k, name)
                out[name] = [val, typ]
            except OSError:
                out[name] = None
    return out


def _notify_inet():
    try:
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        w.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
    except Exception:
        pass


def set_system_pac():
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ,
                          f"{PROXY_URL}/proxy.pac?t={int(time.time() * 1000)}")
    _notify_inet()


def restore_proxy_settings(saved: dict):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY, 0, winreg.KEY_SET_VALUE) as k:
        for name in PROXY_VALUES:
            v = saved.get(name)
            if v is None:
                try:
                    winreg.DeleteValue(k, name)
                except OSError:
                    pass
            else:
                winreg.SetValueEx(k, name, 0, v[1], v[0])
    _notify_inet()


def remove_our_pac() -> bool:
    """Yedek yoksa bile, bizim PAC adresimiz kaldıysa temizler."""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
            val, _ = winreg.QueryValueEx(k, "AutoConfigURL")
            if f"127.0.0.1:{PROXY_PORT}" in str(val):
                winreg.DeleteValue(k, "AutoConfigURL")
                _notify_inet()
                return True
    except OSError:
        pass
    return False


# ------------------------------------------- yeniden başlatma güvencesi
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "DNSKalkanKurtarma"


FROZEN = bool(getattr(sys, "frozen", False))  # PyInstaller ile .exe olarak mı çalışıyoruz?
RES_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))  # gorseller/ burada


def self_cmd(args: list[str], console: bool = False) -> list[str]:
    """Bu programı verilen argümanlarla yeniden çalıştıracak komut (exe veya betik)."""
    if FROZEN:
        return [sys.executable] + args
    exe = sys.executable
    alt = os.path.join(os.path.dirname(exe), "python.exe" if console else "pythonw.exe")
    if os.path.exists(alt):
        exe = alt
    return [exe, os.path.abspath(__file__)] + args


def set_boot_cleanup(on: bool):
    """Koruma açıkken bilgisayar kapanırsa, bir sonraki oturum açılışında
    proxy ayarını otomatik geri alacak tek seferlik bir başlangıç komutu."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if on:
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, subprocess.list2cmdline(self_cmd(["--restore"])))
        else:
            try:
                winreg.DeleteValue(k, RUN_NAME)
            except OSError:
                pass


# ===================================================================== yedek
def read_backup() -> dict | None:
    try:
        with open(BACKUP_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _write_backup(b: dict):
    ensure_dir()
    tmp = BACKUP_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(b, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, BACKUP_PATH)


def save_proxy_backup():
    b = read_backup() or {}
    b["zaman"] = time.strftime("%Y-%m-%d %H:%M:%S")
    cur = read_proxy_settings()
    acu = cur.get("AutoConfigURL")
    if acu and f"127.0.0.1:{PROXY_PORT}" in str(acu[0]):
        cur["AutoConfigURL"] = None  # önceki bir oturumdan kalan kendi ayarımız; yedeğe alma
    b["proxy"] = cur
    _write_backup(b)


def restore_proxy_from_backup() -> bool:
    """Yedekteki proxy ayarlarını geri yükler. Eski sürümden kalan DNS kısmı varsa dosyada bırakır."""
    b = read_backup()
    did = False
    if b and b.get("proxy") is not None:
        restore_proxy_settings(b["proxy"])
        did = True
    elif remove_our_pac():
        did = True
    if b is not None:
        b.pop("proxy", None)
        if b.get("adapters"):
            _write_backup(b)
        else:
            try:
                os.remove(BACKUP_PATH)
            except OSError:
                pass
    return did


# ---- v1'den kalan sistem DNS değişikliklerini geri almak (yönetici gerekir)
def run_ps(script: str) -> str:
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-Command", script], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", creationflags=CREATE_NO_WINDOW)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "PowerShell hatası")
    return r.stdout


def restore_legacy_dns() -> bool:
    b = read_backup()
    if not b or not b.get("adapters"):
        return False
    lines = []
    for a in b["adapters"]:
        idx = int(a["ifIndex"])
        static = [x for x in a.get("static_v4", []) + a.get("static_v6", []) if x not in ("127.0.0.1", "::1")]
        lines.append(f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses -ErrorAction SilentlyContinue")
        if static:
            lst = ",".join("'" + s.replace("'", "") + "'" for s in static)
            lines.append(f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses @({lst}) -ErrorAction SilentlyContinue")
    lines.append("Clear-DnsClientCache")
    run_ps("\n".join(lines))
    b.pop("adapters", None)
    if b.get("proxy") is not None:
        _write_backup(b)
    else:
        os.remove(BACKUP_PATH)
    return True


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_elevated(args: list[str]):
    cmd = self_cmd(args, console=True)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", cmd[0], subprocess.list2cmdline(cmd[1:]), None, 1)


# ===================================================================== Discord
def find_discord_updater() -> str | None:
    base = os.environ.get("LOCALAPPDATA", "")
    for name in ("Discord", "DiscordPTB", "DiscordCanary"):
        p = os.path.join(base, name, "Update.exe")
        if os.path.exists(p):
            return p
    return None


def launch_discord() -> bool:
    upd = find_discord_updater()
    if not upd:
        log("Discord masaüstü uygulaması bulunamadı.")
        return False
    exe = {"Discord": "Discord.exe", "DiscordPTB": "DiscordPTB.exe",
           "DiscordCanary": "DiscordCanary.exe"}[os.path.basename(os.path.dirname(upd))]
    subprocess.run(["taskkill", "/f", "/im", exe], capture_output=True, creationflags=CREATE_NO_WINDOW)
    time.sleep(1.5)
    env = os.environ.copy()
    env.update(HTTPS_PROXY=PROXY_URL, HTTP_PROXY=PROXY_URL, ALL_PROXY=PROXY_URL,
               https_proxy=PROXY_URL, http_proxy=PROXY_URL, NO_PROXY="localhost,127.0.0.1")
    subprocess.Popen([upd, "--processStart", exe, "--process-start-args", f"--proxy-server={PROXY_URL}"],
                     env=env, creationflags=DETACHED_PROCESS, close_fds=True)
    log("Discord tünel ayarlarıyla başlatıldı.")
    return True


# ===================================================================== denetleyici
class Controller:
    def __init__(self):
        self.proxy: DpiProxy | None = None
        self.resolver: Resolver | None = None
        self.active = False

    def turn_on(self, cfg: dict):
        resolver = Resolver(cfg)
        try:
            ips = resolver.lookup_strict("discord.com")
        except Exception as e:
            raise RuntimeError(f"DNS sağlayıcısına ulaşılamadı ({e}). Hiçbir ayar değiştirilmedi.")
        log(f"DoH çalışıyor: discord.com = {ips[0]} ({resolver.last_ms:.0f} ms)")
        proxy = DpiProxy(resolver, cfg["domains"])
        proxy.start()
        try:
            save_proxy_backup()
            set_boot_cleanup(True)
            set_system_pac()
        except Exception:
            proxy.stop()
            restore_proxy_from_backup()
            set_boot_cleanup(False)
            raise
        self.proxy, self.resolver, self.active = proxy, resolver, True
        log(f"AÇIK: {len(cfg['domains'])} site tünelleniyor ({PROXY_URL}).")

    def turn_off(self):
        try:
            restore_proxy_from_backup()
            set_boot_cleanup(False)
            log("KAPALI: Windows proxy ayarları eski haline getirildi.")
        finally:
            if self.proxy:
                self.proxy.stop()
            self.proxy = self.resolver = None
            self.active = False

    def update_domains(self, domains: list[str]):
        if self.proxy:
            self.proxy.domains = list(domains)
            set_system_pac()  # tarayıcılar PAC'i yeniden okusun


def connection_test(ctl: Controller, cfg: dict) -> list[tuple[str, str, str]]:
    """(anahtar, durum, açıklama) listesi döndürür. durum: ok / warn / fail / idle"""
    res = []
    try:
        sys_ip = socket.gethostbyname("discord.com")
        bad = sys_ip.startswith(("195.175.254.", "0.", "127."))
        res.append(("isp", "warn" if bad else "ok",
                    f"{sys_ip} · sahte adres, ISS engelliyor" if bad else f"{sys_ip} · engel görünmüyor"))
    except Exception as e:
        res.append(("isp", "warn", f"çözülemedi ({type(e).__name__})"))
    try:
        r = ctl.resolver or Resolver(cfg)
        ips = r.lookup_strict("discord.com")
        res.append(("doh", "ok", f"{ips[0]} · {r.last_ms:.0f} ms"))
    except Exception as e:
        res.append(("doh", "fail", f"ulaşılamadı ({type(e).__name__})"))
    if ctl.active:
        try:
            t = time.perf_counter()
            conn = http.client.HTTPSConnection("127.0.0.1", PROXY_PORT, timeout=12, context=SSL_CTX)
            conn.set_tunnel("discord.com", 443)
            conn.request("GET", "/api/v9/gateway")
            st = conn.getresponse().status
            conn.close()
            res.append(("tun", "ok" if st < 500 else "fail",
                        f"HTTP {st} · {(time.perf_counter() - t) * 1000:.0f} ms"))
        except Exception as e:
            res.append(("tun", "fail", f"erişilemedi ({type(e).__name__})"))
    else:
        res.append(("tun", "idle", "korumayı açınca test edilir"))
    for k, st, msg in res:
        log(f"Test [{k}] {st}: {msg}")
    return res


# ===================================================================== arayüz
BG = "#0b0d14"
SURF = "#121624"
SURF2 = "#1a1f30"
LINE = "#262c40"
TEXT = "#eef1f8"
SUB = "#8a93a8"
DIM = "#5b6378"
VIOLET = "#8b5cf6"
VIOLET_H = "#a78bfa"
CYAN = "#22d3ee"
GREEN = "#22c55e"
RED = "#f43f5e"
AMBER = "#f59e0b"

PROVIDER_INFO = {
    "Cloudflare": "En hızlı · 1.1.1.1",
    "Google": "Kararlı · 8.8.8.8",
    "AdGuard": "Reklam süzgeçli",
    "OpenDNS": "Cisco altyapısı",
    "Özel sunucu": "Kendi DoH adresin veya IP",
}


def _blend(c1: str, c2: str, t: float) -> str:
    t = max(0.0, min(1.0, t))
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox
    from tkinter import font as tkfont

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    try:  # görev çubuğunda Python yerine kendi simgemiz görünsün
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("WESAR.DNSKalkan")
    except Exception:
        pass

    cfg = load_config()
    ctl = Controller()
    logq: queue.Queue = queue.Queue()
    _listeners.append(logq.put)

    root = tk.Tk()
    root.withdraw()
    S = root.winfo_fpixels("1i") / 96.0

    def px(v):
        return int(round(v * S))

    fams = set(tkfont.families())
    FD = "Segoe UI Variable Display" if "Segoe UI Variable Display" in fams else "Segoe UI"
    FT = "Segoe UI Variable Text" if "Segoe UI Variable Text" in fams else "Segoe UI"

    def F(size, weight="normal", display=False):
        return (FD if display else FT, size, weight)

    W, H = px(440), px(738)
    root.title(f"DNS Kalkan — WESAR")
    root.configure(bg=BG)
    root.resizable(False, False)
    root.minsize(W, H)
    root.maxsize(W, H)
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{W}x{H}+{max(0, (sw - W) // 2)}+{max(0, (sh - px(48) - H - px(32)) // 2)}")

    # pencere ve görev çubuğu simgesi (WESAR kalkanı)
    gdir = os.path.join(RES_DIR, "gorseller")
    try:
        root.iconbitmap(default=os.path.join(gdir, "simge.ico"))
    except Exception as e:
        log(f"Simge yüklenemedi: {e}")

    style = ttk.Style()
    style.theme_use("clam")
    style.layout("D.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
        "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})], "sticky": "ns"})])
    style.configure("D.Vertical.TScrollbar", troughcolor=SURF, background=LINE, bordercolor=SURF,
                    lightcolor=LINE, darkcolor=LINE, gripcount=0, width=px(6))
    style.map("D.Vertical.TScrollbar", background=[("active", DIM)])

    def rrect(cv, x1, y1, x2, y2, r, **kw):
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2,
               x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return cv.create_polygon(pts, smooth=True, **kw)

    # ------------------------------------------------------------ bileşenler
    class Btn(tk.Label):
        def __init__(self, master, text, command, bg=SURF2, hover=LINE, fg=TEXT, font=None, padx=14, pady=7):
            super().__init__(master, text=text, bg=bg, fg=fg, font=font or F(9, "bold"), cursor="hand2",
                             padx=px(padx), pady=px(pady))
            self.c = {"bg": bg, "hover": hover, "fg": fg}
            self._cmd, self.enabled = command, True
            self.bind("<Enter>", lambda e: self.enabled and self.config(bg=self.c["hover"]))
            self.bind("<Leave>", lambda e: self.config(bg=self.c["bg"] if self.enabled else SURF2))
            self.bind("<Button-1>", lambda e: self.enabled and self._cmd())

        def set_enabled(self, on: bool, text=None):
            self.enabled = on
            if text:
                self.config(text=text)
            self.config(bg=self.c["bg"] if on else SURF2, fg=self.c["fg"] if on else DIM,
                        cursor="hand2" if on else "arrow")

    class Switch(tk.Canvas):
        def __init__(self, master, value, on_change, bg=SURF):
            super().__init__(master, width=px(38), height=px(21), bg=bg, highlightthickness=0, cursor="hand2")
            self.value, self.on_change, self.enabled = value, on_change, True
            self.bind("<Button-1>", self._toggle)
            self.draw()

        def _toggle(self, _=None):
            if not self.enabled:
                return
            self.value = not self.value
            self.draw()
            self.on_change(self.value)

        def draw(self):
            self.delete("all")
            w, h = px(38), px(21)
            col = VIOLET if self.value else LINE
            rrect(self, 1, 1, w - 1, h - 1, h / 2 - 1, fill=col, outline=col)
            x = w - h / 2 if self.value else h / 2
            r = h / 2 - px(3.5)
            self.create_oval(x - r, h / 2 - r, x + r, h / 2 + r, fill="white", outline="white")

    def placeholder(entry, var, text):
        def fin(_=None):
            if var.get() == text:
                var.set("")
                entry.config(fg=TEXT)

        def fout(_=None):
            if not var.get().strip():
                var.set(text)
                entry.config(fg=DIM)
        entry.bind("<FocusIn>", fin)
        entry.bind("<FocusOut>", fout)
        fout()

    def entry(parent, var):
        return tk.Entry(parent, textvariable=var, bg=SURF2, fg=TEXT, insertbackground=TEXT, relief="flat",
                        font=F(10), highlightthickness=1, highlightbackground=LINE, highlightcolor=VIOLET,
                        disabledbackground=SURF, disabledforeground=DIM)

    ui = {"phase": 0.0, "busy": False, "hover": False, "on_since": None, "tab": "sites"}

    # ============================================================ ARKA PLAN
    bgc = tk.Canvas(root, width=W, height=H, bg=BG, highlightthickness=0)
    bgc.place(x=0, y=0, width=W, height=H)
    bg_img = None
    try:
        pct = min((100, 125, 150, 175, 200), key=lambda p: abs(p - S * 100))
        cand = os.path.join(gdir, f"arka_plan@{pct}.png")
        if os.path.exists(cand):
            bg_img = tk.PhotoImage(file=cand)
            bgc.create_image(0, 0, anchor="nw", image=bg_img)
    except Exception as e:
        log(f"Arka plan yüklenemedi: {e}")
    root._bg_img = bg_img  # çöp toplayıcı silmesin

    # ============================================================ ÜST BAR
    top = bgc
    # kalkan logosu (uygulama simgesiyle aynı)
    want = px(42)
    lsize = min((32, 40, 48, 64, 96), key=lambda n: (n < want, abs(n - want)))
    sx, s = px(16), lsize
    sy = px(31) - s // 2
    try:
        root._logo = tk.PhotoImage(file=os.path.join(gdir, "simge", f"simge_{lsize}.png"))
        top.create_image(sx, sy, anchor="nw", image=root._logo)
    except Exception:
        top.create_text(sx + s / 2, sy + s / 2, text="W", fill=VIOLET_H, font=F(16, "bold", True))
    top.create_text(sx + s + px(8), px(24), text="DNS Kalkan", anchor="w", fill=TEXT, font=F(15, "bold", True))
    top.create_text(sx + s + px(9), px(44), text="by W E S A R", anchor="w", fill=VIOLET_H, font=F(7, "bold"))
    pill_bg = rrect(top, W - px(140), px(18), W - px(18), px(44), px(13), fill="#2a1520", outline="")
    pill_t = top.create_text(W - px(79), px(31), text="●  KORUMASIZ", fill=RED, font=F(8, "bold"))

    # ============================================================ HERO
    HY, HH = px(62), px(222)
    hero = bgc
    cx, cy, R = W // 2, HY + px(88), px(54)
    glows = [hero.create_oval(cx - R - px(34 - i * 8), cy - R - px(34 - i * 8), cx + R + px(34 - i * 8),
                              cy + R + px(34 - i * 8), fill="", outline="", width=1) for i in range(4)]
    track = hero.create_oval(cx - R - px(9), cy - R - px(9), cx + R + px(9), cy + R + px(9),
                             outline=LINE, width=px(3))
    arc1 = hero.create_arc(cx - R - px(9), cy - R - px(9), cx + R + px(9), cy + R + px(9), start=90, extent=0,
                           style="arc", outline=CYAN, width=px(3))
    arc2 = hero.create_arc(cx - R - px(9), cy - R - px(9), cx + R + px(9), cy + R + px(9), start=270, extent=0,
                           style="arc", outline=VIOLET, width=px(3))
    disc = hero.create_oval(cx - R, cy - R, cx + R, cy + R, fill=SURF2, outline=LINE, width=px(2), tags="pwr")
    ir = px(21)
    icon_arc = hero.create_arc(cx - ir, cy - ir + px(3), cx + ir, cy + ir + px(3), start=125, extent=290,
                               style="arc", outline=RED, width=px(5), tags="pwr")
    icon_line = hero.create_line(cx, cy - ir - px(3), cx, cy + px(2), fill=RED, width=px(5), capstyle="round",
                                 tags="pwr")
    title_t = hero.create_text(cx, cy + R + px(36), text="Korumasız", fill=TEXT, font=F(18, "bold", True))
    sub_t = hero.create_text(cx, cy + R + px(59), text="Başlatmak için düğmeye dokun", fill=SUB, font=F(9))

    def hover(on):
        ui["hover"] = on
        hero.config(cursor="hand2" if on and not ui["busy"] else "")

    hero.tag_bind("pwr", "<Enter>", lambda e: hover(True))
    hero.tag_bind("pwr", "<Leave>", lambda e: hover(False))
    hero.tag_bind("pwr", "<Button-1>", lambda e: toggle())

    # ============================================================ İSTATİSTİK
    stat_v = {}
    MX = px(18)  # kenar boşluğu
    SY = HY + HH  # istatistik kutularının üstü
    tile_w = (W - 2 * MX - 2 * px(8)) // 3
    tiles = []
    for i, (key, icon, cap) in enumerate((("conn", "⇄", "Bağlantı"), ("dns", "◎", "DoH sorgusu"),
                                          ("ms", "⚡", "Gecikme"))):
        f = tk.Frame(bgc, bg=SURF, highlightthickness=1, highlightbackground=LINE)
        tiles.append(f)
        row = tk.Frame(f, bg=SURF)
        row.pack(anchor="w", padx=px(12), pady=(px(8), 0))
        tk.Label(row, text=icon, bg=SURF, fg=VIOLET_H, font=F(10, "bold")).pack(side="left")
        v = tk.Label(row, text="—", bg=SURF, fg=DIM, font=F(13, "bold", True))
        v.pack(side="left", padx=(px(6), 0))
        tk.Label(f, text=cap, bg=SURF, fg=SUB, font=F(8)).pack(anchor="w", padx=px(12), pady=(0, px(8)))
        stat_v[key] = v
    root.update_idletasks()
    tile_h = max(t.winfo_reqheight() for t in tiles)
    for i, t in enumerate(tiles):
        bgc.create_window(MX + i * (tile_w + px(8)), SY, anchor="nw", window=t, width=tile_w, height=tile_h)

    # ============================================================ SEKMELER (kart)
    CY = SY + tile_h + px(10)
    tcard = tk.Frame(bgc, bg=SURF, highlightthickness=1, highlightbackground=LINE)
    tabbar = tk.Frame(tcard, bg=SURF)
    tabbar.pack(fill="x", padx=px(14), pady=(px(10), 0))
    tk.Frame(tcard, bg=LINE, height=1).pack(fill="x")
    tabs_btn = {}
    body = tk.Frame(tcard, bg=SURF, height=px(222))
    body.pack(fill="x")
    body.pack_propagate(False)
    pages = {}

    def show_tab(name):
        ui["tab"] = name
        for k, (lbl, bar) in tabs_btn.items():
            sel = k == name
            lbl.config(fg=TEXT if sel else SUB)
            bar.config(bg=VIOLET if sel else SURF)
        for k, p in pages.items():
            if k == name:
                p.place(x=0, y=0, relwidth=1, relheight=1)
            else:
                p.place_forget()

    for key, label in (("sites", "Siteler"), ("settings", "Ayarlar"), ("test", "Test"), ("log", "Kayıt")):
        col = tk.Frame(tabbar, bg=SURF, cursor="hand2")
        col.pack(side="left", padx=(0, px(18)))
        lbl = tk.Label(col, text=label, bg=SURF, fg=SUB, font=F(10, "bold"), cursor="hand2")
        lbl.pack(pady=(0, px(6)))
        bar = tk.Frame(col, bg=SURF, height=px(2))
        bar.pack(fill="x")
        for w in (col, lbl):
            w.bind("<Button-1>", lambda e, k=key: show_tab(k))
        tabs_btn[key] = (lbl, bar)
        pages[key] = tk.Frame(body, bg=SURF)

    # ------------------------------------------------------------ Siteler
    pg = pages["sites"]
    arow = tk.Frame(pg, bg=SURF)
    arow.pack(fill="x", padx=px(12), pady=(px(12), px(8)))
    dom_var = tk.StringVar()
    dom_ent = entry(arow, dom_var)
    dom_ent.pack(side="left", fill="x", expand=True, ipady=px(5))
    PH = "site ekle — örn. wattpad.com"
    placeholder(dom_ent, dom_var, PH)
    Btn(arow, "Ekle", lambda: add_domain(), bg=VIOLET, hover=VIOLET_H, fg="white").pack(side="left",
                                                                                         padx=(px(8), 0))
    lwrap = tk.Frame(pg, bg=SURF)
    lwrap.pack(fill="both", expand=True, padx=(px(6), px(6)))
    lcv = tk.Canvas(lwrap, bg=SURF, highlightthickness=0)
    sb = ttk.Scrollbar(lwrap, orient="vertical", command=lcv.yview, style="D.Vertical.TScrollbar")
    lcv.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y", pady=px(2))
    lcv.pack(side="left", fill="both", expand=True)
    inner = tk.Frame(lcv, bg=SURF)
    inner_id = lcv.create_window(0, 0, anchor="nw", window=inner)
    inner.bind("<Configure>", lambda e: lcv.configure(scrollregion=lcv.bbox("all")))
    lcv.bind("<Configure>", lambda e: lcv.itemconfig(inner_id, width=e.width))

    def wheel(e):
        if ui["tab"] == "sites":
            lcv.yview_scroll(int(-e.delta / 120), "units")
    root.bind_all("<MouseWheel>", wheel)

    sfoot = tk.Frame(pg, bg=SURF)
    sfoot.pack(fill="x", padx=px(12), pady=(px(4), px(8)))
    count_l = tk.Label(sfoot, text="", bg=SURF, fg=SUB, font=F(8))
    count_l.pack(side="left")
    dlink = tk.Label(sfoot, text="+ Discord profilini ekle", bg=SURF, fg=VIOLET_H, font=F(8, "bold"),
                     cursor="hand2")
    dlink.pack(side="right")
    dlink.bind("<Button-1>", lambda e: add_discord())

    def render_sites():
        for w in inner.winfo_children():
            w.destroy()
        for d in cfg["domains"]:
            row = tk.Frame(inner, bg=SURF)
            row.pack(fill="x")
            col = VIOLET_H if d in DISCORD_PROFILE else CYAN
            dot = tk.Label(row, text="●", fg=col, bg=SURF, font=F(7))
            dot.pack(side="left", padx=(px(8), px(8)))
            name = tk.Label(row, text=d, fg=TEXT, bg=SURF, font=F(10), anchor="w")
            name.pack(side="left", fill="x", expand=True, pady=px(4))
            x = tk.Label(row, text="✕", fg=DIM, bg=SURF, font=F(9, "bold"), cursor="hand2", padx=px(8))
            x.pack(side="right", padx=(0, px(4)))
            parts = (row, dot, name, x)

            def on(e, p=parts):
                for w in p:
                    w.config(bg=SURF2)

            def off(e, p=parts):
                for w in p:
                    w.config(bg=SURF)
            for w in parts:
                w.bind("<Enter>", on)
                w.bind("<Leave>", off)
            x.bind("<Enter>", lambda e, x=x, p=parts: (on(e, p), x.config(fg=RED)))
            x.bind("<Leave>", lambda e, x=x, p=parts: (off(e, p), x.config(fg=DIM)))
            x.bind("<Button-1>", lambda e, d=d: remove_domain(d))
        n = len(cfg["domains"])
        count_l.config(text=f"{n} site tünelleniyor" if ctl.active else f"{n} site listede")
        lcv.yview_moveto(0)

    # ------------------------------------------------------------ Ayarlar
    pg = pages["settings"]
    prov_head = tk.Label(pg, text="DNS SAĞLAYICI", bg=SURF, fg=SUB, font=F(8, "bold"))
    prov_head.pack(anchor="w", padx=px(14), pady=(px(10), px(6)))
    grid = tk.Frame(pg, bg=SURF)
    grid.pack(fill="x", padx=px(12))
    grid.columnconfigure(0, weight=1, uniform="p")
    grid.columnconfigure(1, weight=1, uniform="p")
    prov_var = tk.StringVar(value=cfg["provider"])
    custom_var = tk.StringVar(value=cfg["custom"])
    cards = {}
    CPH = "https://sunucum.com/dns-query  ya da  1.2.3.4"

    def make_card(key, r, c, span=1):
        f = tk.Frame(grid, bg=SURF2, highlightthickness=1, highlightbackground=LINE, cursor="hand2")
        f.grid(row=r, column=c, columnspan=span, sticky="nsew", padx=px(3), pady=px(3))
        dot = tk.Canvas(f, width=px(14), height=px(14), bg=SURF2, highlightthickness=0, cursor="hand2")
        dot.pack(side="left", padx=(px(10), px(8)), pady=px(6))
        txt = tk.Frame(f, bg=SURF2)
        txt.pack(side="left", fill="x", expand=True, pady=px(4))
        t1 = tk.Label(txt, text=key, bg=SURF2, fg=TEXT, font=F(9, "bold"), anchor="w")
        t1.pack(anchor="w")
        t2 = tk.Label(txt, text=PROVIDER_INFO[key], bg=SURF2, fg=SUB, font=F(7), anchor="w")
        t2.pack(anchor="w")
        for w in (f, dot, txt, t1, t2):
            w.bind("<Button-1>", lambda e, k=key: select_provider(k))
        cards[key] = (f, dot, (txt, t1, t2))
        return f

    make_card("Cloudflare", 0, 0)
    make_card("Google", 0, 1)
    make_card("AdGuard", 1, 0)
    make_card("OpenDNS", 1, 1)
    ozel = make_card("Özel sunucu", 2, 0, span=2)
    custom_ent = entry(ozel, custom_var)
    placeholder(custom_ent, custom_var, CPH)

    def paint_cards():
        locked = ctl.active or ui["busy"]
        for k, (f, dot, parts) in cards.items():
            sel = prov_var.get() == k
            f.config(highlightbackground=VIOLET if sel else LINE, cursor="arrow" if locked else "hand2")
            dot.delete("all")
            d = px(14)
            dot.create_oval(1, 1, d - 1, d - 1, outline=VIOLET if sel else DIM, width=px(2))
            if sel:
                dot.create_oval(px(4), px(4), d - px(4), d - px(4), fill=VIOLET, outline=VIOLET)
        if prov_var.get() == "Özel sunucu":
            cards["Özel sunucu"][2][2].pack_forget()
            custom_ent.pack(side="right", fill="x", expand=True, padx=(0, px(8)), ipady=px(3))
            custom_ent.config(state="disabled" if locked else "normal")
        else:
            custom_ent.pack_forget()
            cards["Özel sunucu"][2][2].pack(anchor="w")
        prov_head.config(text="DNS SAĞLAYICI  ·  değiştirmek için korumayı kapat" if locked else "DNS SAĞLAYICI")

    def select_provider(k):
        if ctl.active or ui["busy"]:
            toast("Sağlayıcıyı değiştirmek için önce korumayı kapat", AMBER)
            return
        prov_var.set(k)
        persist()
        paint_cards()

    swrow = tk.Frame(pg, bg=SURF)
    swrow.pack(fill="x", padx=px(14), pady=(px(10), 0))

    def on_switch(v):
        cfg["launch_discord"] = v
        persist()
        toast("Discord korumayla birlikte açılacak" if v else "Discord otomatik açılmayacak")

    Switch(swrow, cfg["launch_discord"], on_switch).pack(side="left")
    tk.Label(swrow, text="Korumayı açınca Discord'u da başlat", bg=SURF, fg=TEXT, font=F(9)).pack(
        side="left", padx=px(10))

    # ------------------------------------------------------------ Test
    pg = pages["test"]
    tk.Label(pg, text="BAĞLANTI TESTİ", bg=SURF, fg=SUB, font=F(8, "bold")).pack(anchor="w", padx=px(14),
                                                                                   pady=(px(10), px(4)))
    trows = {}
    for key, title in (("isp", "İnternet sağlayıcın (ISS) DNS'i"), ("doh", "Şifreli DNS (DoH)"),
                       ("tun", "Discord tüneli")):
        r = tk.Frame(pg, bg=SURF2)
        r.pack(fill="x", padx=px(12), pady=px(3))
        ic_ = tk.Label(r, text="○", bg=SURF2, fg=DIM, font=F(12, "bold"), width=2)
        ic_.pack(side="left", padx=(px(6), px(4)), pady=px(5))
        tx = tk.Frame(r, bg=SURF2)
        tx.pack(side="left", fill="x", expand=True)
        tk.Label(tx, text=title, bg=SURF2, fg=TEXT, font=F(9, "bold"), anchor="w").pack(anchor="w")
        dl = tk.Label(tx, text="henüz test edilmedi", bg=SURF2, fg=SUB, font=F(8), anchor="w")
        dl.pack(anchor="w")
        trows[key] = (ic_, dl)
    tbtn = Btn(pg, "Testi çalıştır", lambda: do_test(), bg=VIOLET, hover=VIOLET_H, fg="white")
    tbtn.pack(anchor="e", padx=px(12), pady=(px(6), 0))

    def show_test(res):
        icons = {"ok": ("✓", GREEN), "warn": ("!", AMBER), "fail": ("✕", RED), "idle": ("○", DIM)}
        for k, st, msg in res or []:
            ic_, dl = trows[k]
            ch, col = icons[st]
            ic_.config(text=ch, fg=col)
            dl.config(text=msg, fg=col if st in ("fail", "warn") else SUB)
        tbtn.set_enabled(True, "Testi çalıştır")

    def do_test():
        tbtn.set_enabled(False, "Test ediliyor…")
        for ic_, dl in trows.values():
            ic_.config(text="…", fg=CYAN)
        run_bg(lambda: connection_test(ctl, dict(cfg)), show_test)

    # ------------------------------------------------------------ Kayıt
    pg = pages["log"]
    logbox = tk.Text(pg, bg=SURF, fg="#aab2c5", relief="flat", font=("Consolas", 8), padx=px(10),
                     pady=px(8), wrap="word", state="disabled", highlightthickness=0)
    logbox.pack(fill="both", expand=True)

    # ============================================================ EYLEM
    act = Btn(bgc, "▶   Discord'u tünelle başlat", lambda: do_launch(), bg=VIOLET, hover=VIOLET_H,
              fg="white", font=F(11, "bold", True), pady=10)
    root.update_idletasks()
    card_h = tcard.winfo_reqheight()
    bgc.create_window(MX, CY, anchor="nw", window=tcard, width=W - 2 * MX, height=card_h)
    AY = CY + card_h + px(10)
    bgc.create_window(MX, AY, anchor="nw", window=act, width=W - 2 * MX)

    # ============================================================ İMZA (alt bilgi)
    FH = px(46)
    FY = H - FH
    foot = bgc
    seg = 60
    for i in range(seg):  # ince degrade çizgi
        x1 = MX + (W - 2 * MX) * i / seg
        x2 = MX + (W - 2 * MX) * (i + 1) / seg
        t = abs(i / seg - 0.5) * 2
        foot.create_line(x1, FY + px(8), x2, FY + px(8),
                         fill=_blend(_blend(VIOLET, CYAN, i / seg), BG, t * 0.75))
    foot.create_text(MX, FY + px(28), text=f"v{VERSION}  ·  © 2026", anchor="w", fill=DIM, font=F(8))
    sig_font = tkfont.Font(family=FD, size=13, weight="bold")
    letters = "WESAR"
    gap = px(5)
    widths = [sig_font.measure(ch) for ch in letters]
    total = sum(widths) + gap * (len(letters) - 1)
    x = W - MX - total
    sig_ids = []
    for ch, w_ in zip(letters, widths):
        sig_ids.append(foot.create_text(x, FY + px(28), text=ch, anchor="w", font=sig_font, fill=VIOLET))
        x += w_ + gap
    diamond = foot.create_text(W - MX - total - px(10), FY + px(28), text="◆", anchor="e", fill=VIOLET,
                               font=F(8))
    foot.create_text(W - MX - total - px(26), FY + px(28), text="crafted by", anchor="e", fill=SUB,
                     font=F(8))

    # ============================================================ toast
    toast_l = tk.Label(root, text="", bg=SURF2, fg=TEXT, font=F(9, "bold"), padx=px(14), pady=px(7),
                       highlightthickness=1, highlightbackground=LINE)
    toast_job = {"id": None}

    def toast(msg, color=GREEN):
        toast_l.config(text=msg, highlightbackground=color, fg=TEXT)
        toast_l.place(relx=0.5, y=AY - px(8), anchor="s")
        toast_l.lift()
        if toast_job["id"]:
            root.after_cancel(toast_job["id"])
        toast_job["id"] = root.after(2400, toast_l.place_forget)

    # ============================================================ animasyon
    def animate():
        ui["phase"] += 0.045
        ph = ui["phase"]
        on, busy = ctl.active, ui["busy"]
        if busy:
            col, glow = AMBER, AMBER
            hero.itemconfig(arc1, start=(ph * 400) % 360, extent=80, outline=AMBER)
            hero.itemconfig(arc2, start=(ph * 400 + 180) % 360, extent=80, outline=AMBER)
        elif on:
            col = _blend(CYAN, GREEN, (math.sin(ph * 1.3) + 1) / 2)
            glow = col
            hero.itemconfig(arc1, start=(ph * 90) % 360, extent=110, outline=CYAN)
            hero.itemconfig(arc2, start=(ph * 90 + 180) % 360, extent=110, outline=VIOLET)
        else:
            col, glow = RED, RED
            hero.itemconfig(arc1, extent=0)
            hero.itemconfig(arc2, extent=0)
        pulse = (math.sin(ph * 2) + 1) / 2 if on and not busy else 0.3
        for i, g in enumerate(glows):
            hero.itemconfig(g, outline=_blend(BG, glow, (0.10 + 0.12 * i) * (0.5 + 0.5 * pulse)))
        hov = ui["hover"] and not busy
        hero.itemconfig(disc, fill=_blend(SURF2, col, 0.14 if hov else 0.06),
                        outline=_blend(LINE, col, 0.6 if hov else 0.25))
        hero.itemconfig(icon_arc, outline=col)
        hero.itemconfig(icon_line, fill=col)
        for i, sid in enumerate(sig_ids):  # imza parıltısı
            k = (math.sin(ph * 1.6 - i * 0.7) + 1) / 2
            foot.itemconfig(sid, fill=_blend(_blend(VIOLET, CYAN, i / 4), "#ffffff", k * 0.35))
        foot.itemconfig(diamond, fill=_blend(VIOLET, CYAN, (math.sin(ph * 1.6) + 1) / 2))
        root.after(33, animate)

    # ============================================================ davranış
    def persist():
        cv_ = custom_var.get().strip()
        cfg.update(provider=prov_var.get(), custom="" if cv_ == CPH else cv_)
        save_config(cfg)

    def domains_changed():
        render_sites()
        persist()
        set_ui()
        try:
            ctl.update_domains(cfg["domains"])
        except Exception as e:
            log(f"PAC yenilenemedi: {e}")

    def add_domain(*_):
        d = dom_var.get().strip().lower()
        if d == PH.lower() or not d:
            return
        for pre in ("https://", "http://"):
            if d.startswith(pre):
                d = d[len(pre):]
        d = d.split("/")[0].strip(".")
        if d.startswith("www."):
            d = d[4:]
        if "." not in d or " " in d:
            toast("Geçerli bir alan adı yaz (örn. ornek.com)", AMBER)
            return
        if d in cfg["domains"]:
            toast(f"{d} zaten listede", AMBER)
        else:
            cfg["domains"].append(d)
            domains_changed()
            log(f"Eklendi: {d}")
            toast(f"{d} eklendi")
            root.after(50, lambda: lcv.yview_moveto(1.0))
        dom_var.set("")

    def remove_domain(d):
        if d in cfg["domains"]:
            cfg["domains"].remove(d)
            domains_changed()
            log(f"Çıkarıldı: {d}")
            toast(f"{d} çıkarıldı", RED)

    def add_discord():
        new = [d for d in DISCORD_PROFILE if d not in cfg["domains"]]
        cfg["domains"].extend(new)
        domains_changed()
        log(f"Discord profili: {len(new)} yeni site eklendi.")
        toast("Discord profili eklendi" if new else "Discord profili zaten ekli")

    dom_ent.bind("<Return>", add_domain)

    def fmt_up():
        if not ui["on_since"]:
            return ""
        s_ = int(time.time() - ui["on_since"])
        return f"{s_ // 3600:02d}:{s_ % 3600 // 60:02d}:{s_ % 60:02d}"

    def set_ui():
        on, busy = ctl.active, ui["busy"]
        n = len(cfg["domains"])
        if busy:
            hero.itemconfig(title_t, text="Bağlanıyor…" if not on else "Kapatılıyor…", fill=AMBER)
            hero.itemconfig(sub_t, text="Birkaç saniye sürebilir")
        elif on:
            hero.itemconfig(title_t, text="Korumalı", fill=GREEN)
            hero.itemconfig(sub_t, text=f"Discord ve {n} site güvenli tünelde  ·  {fmt_up()}")
        else:
            hero.itemconfig(title_t, text="Korumasız", fill=TEXT)
            hero.itemconfig(sub_t, text="Başlatmak için düğmeye dokun")
        top.itemconfig(pill_t, text="●  KORUMALI" if on else ("●  BEKLE" if busy else "●  KORUMASIZ"),
                       fill=GREEN if on else (AMBER if busy else RED))
        top.itemconfig(pill_bg, fill="#11261b" if on else ("#2a2110" if busy else "#2a1520"))
        act.set_enabled(on and not busy,
                        "▶   Discord'u tünelle başlat" if on else "Discord için önce korumayı aç")
        count_l.config(text=f"{n} site tünelleniyor" if on else f"{n} site listede")
        paint_cards()

    def run_bg(fn, done=None):
        def wrap():
            try:
                res = fn()
            except Exception as e:
                log(f"HATA: {e}")
                root.after(0, lambda m=str(e): messagebox.showerror("DNS Kalkan", m))
                res = None
            root.after(0, lambda: (done and done(res), set_ui()))
        threading.Thread(target=wrap, daemon=True).start()

    def toggle():
        if ui["busy"]:
            return
        persist()
        was_on = ctl.active
        ui["busy"] = True
        set_ui()

        def work():
            if ctl.active:
                ctl.turn_off()
            else:
                ctl.turn_on(dict(cfg, domains=list(cfg["domains"])))
                if cfg["launch_discord"]:
                    launch_discord()
            return True

        def done(ok):
            ui["busy"] = False
            if ctl.active and not was_on:
                ui["on_since"] = time.time()
                toast("Koruma açık" + (" · Discord başlatılıyor" if cfg["launch_discord"] else ""))
            elif not ctl.active and was_on:
                ui["on_since"] = None
                toast("Koruma kapatıldı · ayarlar geri yüklendi", SUB)
        run_bg(work, done)

    def do_launch():
        if ctl.active:
            run_bg(launch_discord, lambda r: r and toast("Discord tünelle başlatılıyor"))

    def pump():
        while not logq.empty():
            logbox.config(state="normal")
            logbox.insert("end", logq.get() + "\n")
            if int(logbox.index("end-1c").split(".")[0]) > 400:
                logbox.delete("1.0", "100.0")
            logbox.see("end")
            logbox.config(state="disabled")
        if ctl.active and ctl.proxy and ctl.resolver:
            stat_v["conn"].config(text=str(ctl.proxy.total), fg=TEXT)
            stat_v["dns"].config(text=str(ctl.resolver.queries), fg=TEXT)
            ms = ctl.resolver.last_ms
            stat_v["ms"].config(text=f"{ms:.0f} ms" if ms else "—", fg=GREEN if ctl.resolver.ok else RED)
            if not ui["busy"]:
                hero.itemconfig(sub_t, text=f"Discord ve {len(cfg['domains'])} site güvenli tünelde  ·  {fmt_up()}")
        else:
            for v in stat_v.values():
                v.config(text="—", fg=DIM)
        root.after(500, pump)

    def on_close():
        if ctl.active:
            try:
                ctl.turn_off()
            except Exception as e:
                messagebox.showerror("DNS Kalkan", f"Geri yükleme hatası: {e}\nkurtarma.bat dosyasını çalıştır.")
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    def on_map(_=None):
        if root.state() == "normal" and (root.winfo_width() < W // 2 or root.winfo_height() < H // 2):
            root.geometry(f"{W}x{H}")
    root.bind("<Map>", on_map)

    # ============================================================ başlangıç
    render_sites()
    show_tab("sites")
    set_ui()

    def dark_titlebar():
        try:
            root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            dwm = ctypes.windll.dwmapi
            dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(1)), 4)    # koyu mod
            dwm.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(ctypes.c_int(0x00140D0B)), 4)  # başlık rengi
            dwm.DwmSetWindowAttribute(hwnd, 36, ctypes.byref(ctypes.c_int(0x00F8F1EE)), 4)  # başlık yazısı
            dwm.DwmSetWindowAttribute(hwnd, 34, ctypes.byref(ctypes.c_int(0x00402C26)), 4)  # kenarlık
            ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0027)  # çerçeveyi yenile
        except Exception:
            pass

    try:
        b = read_backup()
        set_boot_cleanup(False)
        if restore_proxy_from_backup():
            log("Önceki oturum düzgün kapanmamış; proxy ayarları geri yüklendi.")
            root.after(600, lambda: toast("Önceki oturumdan kalan ayar temizlendi", AMBER))
        if b and b.get("adapters"):
            if messagebox.askyesno("DNS Kalkan", "Eski sürümün değiştirdiği sistem DNS ayarları hâlâ duruyor.\n"
                                                 "Şimdi eski haline getirilsin mi? (yönetici izni istenecek)"):
                run_elevated(["--restore-legacy"])
                log("Eski DNS ayarları geri yükleniyor (yönetici penceresi).")
    except Exception as e:
        log(f"Başlangıç kontrolü hatası: {e}")
    log(f"DNS Kalkan v{VERSION} hazır.")

    root.deiconify()
    dark_titlebar()
    animate()
    pump()
    root.mainloop()


# ===================================================================== giriş
def main():
    install_crash_logging()
    args = sys.argv[1:]
    if args[:1] == ["--restore-legacy"]:
        if not is_admin():
            run_elevated(["--restore-legacy"])
            return
        print("Eski DNS ayarları geri yüklendi." if restore_legacy_dns() else "Geri yüklenecek DNS ayarı yok.")
        return
    if args[:1] == ["--restore"]:
        b = read_backup()
        try:
            set_boot_cleanup(False)
        except Exception:
            pass
        did = restore_proxy_from_backup()
        file_log("Kurtarma (--restore): " + ("proxy ayarları geri yüklendi." if did else "değişiklik yok."))
        print("Proxy ayarları geri yüklendi." if did else "Proxy: değişiklik yok.")
        if b and b.get("adapters"):
            if is_admin():
                restore_legacy_dns()
                print("Eski sistem DNS ayarları geri yüklendi.")
            else:
                run_elevated(["--restore-legacy"])
        return
    run_gui()


if __name__ == "__main__":
    main()
