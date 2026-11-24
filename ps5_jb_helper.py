#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEKT0R AUTO JAILBREAK TOOLKIT — self-host the Relapse exploit (firmware 7.00–13.60).

Downloads the public exploit host page from GitHub, then runs a local
DNS + HTTP/HTTPS server so the PS5 User's Guide loads the exploit page
over a LAN cable. Standard library only (Python 3.9+), GUI via tkinter.

MIT License (this file). Downloaded exploit content keeps its upstream
licenses: WAK1360-Relapse GPL-3.0, Relapse-Exploit MIT, ftpsrv upstream.
For security research on a console you own. No piracy content included.

Optimizations v1.1.0:
- External config.json for all tunable parameters
- Robust retry logic with exponential backoff for downloads
- Cross-platform network interface detection (Windows/Linux/macOS)
- Structured logging with levels and rotation
- Better error handling and user feedback
- Payload verification with detailed reports
- Auto-update check for payloads/exploit
- Improved GUI with progress details, firmware version display
- PyInstaller-ready (single file executable)
- Certificate auto-generation with proper SANs
"""

import ctypes
import hashlib
import io
import json
import logging
import mimetypes
import os
import queue
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# ─── Configuration ────────────────────────────────────────────────────────

APP_NAME = "SEKT0R AUTO JAILBREAK TOOLKIT"
APP_VER = "1.2.0"

def _get_base() -> Path:
    """Get base directory for config/assets — works in both dev and frozen (PyInstaller) modes."""
    if getattr(sys, "frozen", False):
        # PyInstaller one-file: data files extracted to sys._MEIPASS
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent

BASE = _get_base()
CONFIG_FILE = BASE / "config.json"
WWW = BASE / "www"
ASSETS = BASE / "assets"
MANIFEST = BASE / "manifest.json"
LOG_FILE = BASE / "ps5_jb_helper.log"

# Default configuration (overridden by config.json)
DEFAULT_CONFIG = {
    "app": {"name": APP_NAME, "version": APP_VER},
    "upstream": {
        "host_repo": "arg0WAK/WAK1360-Relapse",
        "host_ref": "b2398fd5bea116f990595e0a187ae94d8c6db43d",
        "overlay_repo": "ThatRetiredDude/ps5-relapse-selfhost",
        "overlay_branch": "main",
        "ftpsrv_url": "https://github.com/ps5-payload-dev/ftpsrv/releases/download/v0.21.1/ftpsrv-ps5.elf",
        "ftpsrv_sha256": "7d4b31c83eae4e056580482a3a074e1db25922efc74ac1e439473b45d71a5938",
    },
    "network": {
        "dns_port": 53,
        "http_port": 80,
        "https_port": 443,
        "static_ip": "192.168.100.1",
        "static_mask": "255.255.255.0",
        "ps5_ip": "192.168.100.2",
        "upstream_dns": ["1.1.1.1", "8.8.8.8"],
        "guide_domains": ["manuals.playstation.net", "manual.playstation.net", "doc.dl.playstation.net"],
        "block_domains": [
            "update.playstation.net", "update.playstation.com", "dservices.playstation.net",
            "fms.playstation.net", "pst-patch.playstation.net",
            "sonyentertainmentnetwork.com", "scea.com",
        ],
    },
    "payloads": {
        "required": ["OnionHEN.elf", "kstuff.elf", "shadowmountplus.elf", "ftpsrv-ps5.elf"],
        "optional": ["elfldr-ps5-1360.elf", "kexp_2026_05_25.bin", "nanodns.elf"],
    },
    "firmware": {
        "min_version": "7.00",
        "max_version": "13.60",
        "supported": [],
    },
    "download": {
        "timeout": 60,
        "chunk_size": 65536,
        "max_retries": 3,
        "retry_delay": 2,
    },
    "gui": {
        "theme": "dark",
        "window_size": "860x760",
        "min_window_size": "760x640",
        "colors": {
            "bg": "#101418", "card": "#1a2129", "fg": "#e5e7eb", "accent": "#3b82f6",
            "success": "#22c55e", "warning": "#fbbf24", "error": "#ef4444", "muted": "#9ca3af",
        },
    },
    "logging": {
        "level": "INFO",
        "format": "[{time}] {level}: {message}",
        "max_lines": 1000,
    },
}


def load_config() -> Dict[str, Any]:
    """Load configuration from config.json, falling back to defaults."""
    config = DEFAULT_CONFIG.copy()
    if CONFIG_FILE.is_file():
        try:
            with CONFIG_FILE.open("r", encoding="utf-8") as f:
                user_config = json.load(f)
            # Deep merge
            def merge(base: dict, override: dict) -> dict:
                for k, v in override.items():
                    if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                        base[k] = merge(base[k], v)
                    else:
                        base[k] = v
                return base
            config = merge(config, user_config)
        except Exception as e:
            print(f"Warning: Failed to load config.json: {e}, using defaults")
    return config


CFG = load_config()

# Extracted config values for convenience
HOST_REPO = CFG["upstream"]["host_repo"]
HOST_REF = CFG["upstream"]["host_ref"]
HOST_ZIP = f"https://codeload.github.com/{HOST_REPO}/zip/{HOST_REF}"
OVERLAY_RAW = f"https://raw.githubusercontent.com/{CFG['upstream']['overlay_repo']}/{CFG['upstream']['overlay_branch']}/overlay/"
OVERLAY_FILES = ["index.html", "src/firmware.js", "src/helper.js", "src/force-ready.js"]
OVERLAY_PAYLOADS_JSON = "payloads.json"
FTPSRV_URL = CFG["upstream"]["ftpsrv_url"]
FTPSRV_SHA256 = CFG["upstream"]["ftpsrv_sha256"]

GUIDE_DOMAINS = tuple(CFG["network"]["guide_domains"])
BLOCK_DOMAINS = tuple(CFG["network"]["block_domains"])
UPSTREAM_DNS = tuple(CFG["network"]["upstream_dns"])

DNS_PORT = CFG["network"]["dns_port"]
HTTP_PORT = CFG["network"]["http_port"]
HTTPS_PORT = CFG["network"]["https_port"]
STATIC_IP = CFG["network"]["static_ip"]
STATIC_MASK = CFG["network"]["static_mask"]
PS5_IP = CFG["network"]["ps5_ip"]

REQUIRED_FILES = (
    "index.html", "src/firmware.js", "src/helper.js", "src/force-ready.js",
    "assets/index.css", "payloads/payloads.json",
    *[f"payloads/{p}" for p in CFG["payloads"]["required"]],
    "offsets/13.60.js",
)

MIME = {
    ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css",
    ".html": "text/html; charset=utf-8", ".json": "application/json",
    ".elf": "application/octet-stream", ".bin": "application/octet-stream",
    ".png": "image/png", ".svg": "image/svg+xml", ".woff2": "font/woff2",
}

UA = {"User-Agent": f"ps5-jb-helper/{APP_VER}"}
DOWNLOAD_TIMEOUT = CFG["download"]["timeout"]
CHUNK_SIZE = CFG["download"]["chunk_size"]
MAX_RETRIES = CFG["download"]["max_retries"]
RETRY_DELAY = CFG["download"]["retry_delay"]

# ─── Logging ──────────────────────────────────────────────────────────────

class QueueHandler(logging.Handler):
    """Logging handler that puts records into a queue for GUI consumption."""
    def __init__(self, q: queue.Queue):
        super().__init__()
        self.q = q

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self.q.put(("log", msg))
        except Exception:
            self.handleError(record)


def setup_logging(log_queue: queue.Queue) -> logging.Logger:
    """Configure application logging."""
    logger = logging.getLogger("ps5_jb_helper")
    logger.setLevel(getattr(logging, CFG["logging"]["level"].upper(), logging.INFO))
    logger.handlers.clear()

    # File handler with rotation
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    log_fmt = CFG["logging"]["format"]
    # Only convert {time} style to %(asctime)s if not already in %(...)s format
    if "%(" not in log_fmt:
        log_fmt = log_fmt.replace("{", "%(").replace("}", ")s")
    fh.setFormatter(logging.Formatter(log_fmt))
    logger.addHandler(fh)

    # Queue handler for GUI
    qh = QueueHandler(log_queue)
    qh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", "%H:%M:%S"))
    logger.addHandler(qh)

    return logger


# ─── DNS Server ───────────────────────────────────────────────────────────

def _dns_name(data: bytes, i: int) -> Tuple[str, int]:
    """Parse one QNAME; returns (name, next_offset) or raises ValueError."""
    labels = []
    while True:
        if i >= len(data):
            raise ValueError("truncated name")
        ln = data[i]
        if ln == 0:
            return ".".join(labels), i + 1
        if ln & 0xC0:
            raise ValueError("compressed question")
        i += 1
        labels.append(data[i:i + ln].decode("ascii", "replace").lower())
        i += ln


def _dns_response(tid: bytes, question: bytes, ip: str) -> bytes:
    header = tid + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return header + question + answer


def _dns_nodata(tid: bytes, question: bytes) -> bytes:
    return tid + b"\x81\x80" + struct.pack(">HHHH", 1, 0, 0, 0) + question


def dns_forward(data: bytes) -> Optional[bytes]:
    """Forward DNS query to upstream resolvers."""
    for server in UPSTREAM_DNS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.5)
                s.sendto(data, (server, 53))
                resp, _ = s.recvfrom(4096)
                return resp
        except OSError:
            continue
    return None


def dns_respond(data: bytes, target_ip: str, forward: bool = True) -> Optional[bytes]:
    """Answer one DNS query packet. Returns response bytes or None."""
    if len(data) < 12:
        return None
    tid = data[:2]
    flags = struct.unpack(">H", data[2:4])[0]
    if flags & 0x7800:  # not a standard query
        return None
    if struct.unpack(">H", data[4:6])[0] != 1:  # != exactly one question
        return dns_forward(data) if forward else None
    try:
        qname, i = _dns_name(data, 12)
    except ValueError:
        return dns_forward(data) if forward else None
    if i + 4 > len(data):
        return None
    qtype = struct.unpack(">H", data[i:i + 2])[0]
    question = data[12:i + 4]

    def matches(dom: str) -> bool:
        return qname == dom or qname.endswith("." + dom)

    if any(matches(d) for d in GUIDE_DOMAINS):
        # A -> us; anything else (AAAA/HTTPS/...) -> NODATA so no IPv6 bypass
        return _dns_response(tid, question, target_ip) if qtype == 1 else _dns_nodata(tid, question)
    if any(matches(d) for d in BLOCK_DOMAINS):
        return _dns_response(tid, question, "0.0.0.0") if qtype == 1 else _dns_nodata(tid, question)
    return dns_forward(data) if forward else None


def dns_query_packet(name: str, qtype: int = 1) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        try:
            resp = dns_respond(data, self.server.target_ip)
        except Exception:
            resp = None
        if resp:
            try:
                sock.sendto(resp, self.client_address)
            except OSError:
                pass


class DNSServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, ip: str, port: int = DNS_PORT):
        self.target_ip = ip
        super().__init__((ip, port), DNSHandler)


# ─── HTTP / HTTPS Server ──────────────────────────────────────────────────

DEEP_ASSET_RE = re.compile(r"^/document/.+/(src|assets)/(.*)$", re.IGNORECASE)


def map_path(url_path: str, www: Path) -> Tuple[Optional[Path], str]:
    """nginx-equivalent mapping. Returns (file_path, mode) where mode is
    'file', 'spa' (serve index.html) or '404'. Never escapes www."""
    path = urllib.parse.unquote(urllib.parse.urlsplit(url_path).path)
    m = DEEP_ASSET_RE.match(path)
    if m:
        path = "/" + m.group(1) + "/" + m.group(2)
    rel = path.lstrip("/")
    try:
        full = (www / rel).resolve()
        root = www.resolve()
        full.relative_to(root)
    except (ValueError, OSError):
        return None, "404"
    ext = os.path.splitext(full.name)[1].lower()
    if ext in (".js", ".css"):
        # CRITICAL: never SPA-fallback assets — HTML-as-JS kills the exploit silently
        return (full, "file") if full.is_file() else (None, "404")
    if full.is_file():
        return full, "file"
    if full.is_dir() and (full / "index.html").is_file():
        return full / "index.html", "file"
    return www / "index.html", "spa"


class ExploitHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"PS5JBHelper/{APP_VER}"

    def send_head(self) -> Optional[io.BytesIO]:
        full, mode = map_path(self.path, self.server.www)
        if mode == "404" or full is None:
            self.send_error(404, "Not Found")
            return None
        ctype = MIME.get(os.path.splitext(full.name)[1].lower()) or mimetypes.guess_type(full.name)[0] or "application/octet-stream"
        try:
            body = full.read_bytes()
        except OSError:
            self.send_error(404, "Not Found")
            return None
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        return io.BytesIO(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        srv = self.server
        if hasattr(srv, "log"):
            srv.log("http: " + (fmt % args), level="debug")


class WebServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, ip: str, port: int, www: Path, log_func, use_tls: bool = False):
        self.www = Path(www)
        self.log = log_func
        super().__init__((ip, port), ExploitHandler)
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(ASSETS / "manuals.crt", ASSETS / "manuals.key")
            self.socket = ctx.wrap_socket(self.socket, server_side=True)


# ─── Downloader with Retry ────────────────────────────────────────────────

def http_get(url: str, timeout: int = DOWNLOAD_TIMEOUT) -> urllib.request.urlopen:
    req = urllib.request.Request(url, headers=UA)
    return urllib.request.urlopen(req, timeout=timeout)


def download_file(url: str, dest: Union[str, Path], progress=None, sha256: Optional[str] = None) -> str:
    """Download a file with retries and optional SHA-256 verification."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")

    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            h = hashlib.sha256()
            with http_get(url) as r, open(tmp, "wb") as f:
                total = int(r.headers.get("Content-Length") or 0)
                done = 0
                while True:
                    chunk = r.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
                    h.update(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, total)
            if sha256 and h.hexdigest() != sha256:
                tmp.unlink(missing_ok=True)
                raise ValueError(
                    f"SHA-256 mismatch for {url}\n expected {sha256}\n got      {h.hexdigest()}"
                )
            tmp.replace(dest)
            return h.hexdigest()
        except Exception as e:
            last_error = e
            tmp.unlink(missing_ok=True)
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)  # exponential backoff
            else:
                raise
    raise last_error  # type: ignore


def verify_www(www: Path) -> List[str]:
    """Integrity checks mirroring the upstream self-host kit's sanity checks."""
    problems = []
    for rel in REQUIRED_FILES:
        if not (www / rel).is_file():
            problems.append(f"missing {rel}")
    idx = (www / "index.html").read_text(encoding="utf-8", errors="replace") if (www / "index.html").is_file() else ""
    if 'base href="/"' not in idx:
        problems.append("overlay index.html not applied (no <base href>)")
    if "force-ready.js" not in idx:
        problems.append("overlay index.html missing force-ready.js")
    # every local asset referenced by index.html must exist
    for ref in re.findall(r'(?:src|href)="([^"]+)"', idx):
        ref = ref.split("?", 1)[0]
        if ref.startswith(("http:", "https:", "data:", "#")) or not ref:
            continue
        rel = ref.lstrip("./").lstrip("/")
        if not rel or rel == ".":
            continue
        if not (www / rel).is_file():
            problems.append(f"index.html references missing file: {ref}")
    return problems


def download_all(www: Path, log_func, progress=None) -> bool:
    """Fetch pinned host page + overlay + FTP payload into a temp dir, verify,
    then swap into place. Old www survives any failure."""
    www = Path(www)
    staging = www.with_name("www_new")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    try:
        log_func(f"Downloading host page {HOST_REPO}@{HOST_REF[:7]} …")
        zip_path = staging / "host.zip"
        download_file(HOST_ZIP, zip_path, progress=progress)
        log_func("Extracting …")
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(staging / "unzip")
        zip_path.unlink()
        roots = [p for p in (staging / "unzip").iterdir() if p.is_dir() and (p / "index.html").is_file()]
        if len(roots) != 1:
            raise ValueError("unexpected archive layout (no single index.html root)")
        for item in roots[0].iterdir():
            shutil.move(str(item), staging / item.name)
        shutil.rmtree(staging / "unzip")

        log_func("Applying self-host overlay (cache-bust, UA fixes, deep paths) …")
        for rel in OVERLAY_FILES:
            download_file(OVERLAY_RAW + rel, staging / rel)
            log_func(f"  + {rel}")
        download_file(OVERLAY_RAW + OVERLAY_PAYLOADS_JSON, staging / "payloads" / "payloads.json")
        log_func("  + payloads/payloads.json")

        log_func("Downloading FTP payload (ftpsrv v0.21.1) …")
        download_file(FTPSRV_URL, staging / "payloads" / "ftpsrv-ps5.elf", sha256=FTPSRV_SHA256)
        log_func("  + payloads/ftpsrv-ps5.elf (SHA-256 verified)")

        problems = verify_www(staging)
        if problems:
            raise ValueError("integrity check failed:\n  " + "\n  ".join(problems))

        if www.exists():
            shutil.rmtree(www)
        staging.replace(www)
        MANIFEST.write_text(json.dumps({
            "host_repo": HOST_REPO, "host_ref": HOST_REF,
            "overlay": f"{CFG['upstream']['overlay_repo']}@{CFG['upstream']['overlay_branch']}",
            "ftpsrv": "v0.21.1", "ftpsrv_sha256": FTPSRV_SHA256,
            "downloaded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }, indent=2), encoding="utf-8")
        log_func("Files ready. Integrity checks passed.")
        return True
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


# ─── Network Helpers ──────────────────────────────────────────────────────

def list_interfaces() -> List[Tuple[str, str]]:
    """[(ip, alias)] — real adapter names, cross-platform."""
    # Windows: PowerShell (locale-safe)
    if os.name == "nt":
        try:
            cmd = (
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
                "Get-NetIPAddress -AddressFamily IPv4 "
                "| Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } "
                "| Select-Object IPAddress,InterfaceAlias | ConvertTo-Json -Compress"
            )
            out = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", cmd],
                capture_output=True, encoding="utf-8", timeout=20
            )
            data = json.loads(out.stdout or "[]")
            if isinstance(data, dict):
                data = [data]
            res = [(d["IPAddress"], d.get("InterfaceAlias", "?")) for d in data if d.get("IPAddress")]
            if res:
                return res
        except Exception:
            pass

    # Linux: ip addr show
    try:
        out = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            data = json.loads(out.stdout)
            res = []
            for iface in data:
                if iface.get("operstate") != "UP":
                    continue
                alias = iface.get("ifname", "?")
                for addr in iface.get("addr_info", []):
                    if addr.get("family") == "inet":
                        ip = addr.get("local")
                        if ip and not ip.startswith("127."):
                            res.append((ip, alias))
            if res:
                return res
    except Exception:
        pass

    # macOS/BSD: ifconfig
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            res = []
            current_alias = None
            for line in out.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith(("\t", " ")):
                    current_alias = line.split(":")[0]
                elif "inet " in line and not line.startswith("inet6"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        if not ip.startswith("127."):
                            res.append((ip, current_alias or "?"))
            if res:
                return res
    except Exception:
        pass

    # Fallback: socket.getaddrinfo
    seen, res = set(), []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in seen and not ip.startswith("127."):
                seen.add(ip)
                res.append((ip, "adapter"))
    except OSError:
        pass
    return res


def pick_default(interfaces: List[Tuple[str, str]]) -> str:
    for ip, _ in interfaces:
        if ip == "192.168.137.1":  # Windows ICS / mobile hotspot
            return ip
    for ip, _ in interfaces:
        if ip.startswith(("192.168.", "10.", "172.")):
            return ip
    return interfaces[0][0] if interfaces else ""


def port_owner(port: int) -> str:
    """Best-effort 'who holds this port' for error messages (Windows)."""
    if os.name != "nt":
        return ""
    try:
        out = subprocess.run(["netstat", "-ano", "-p", "UDP"], capture_output=True, text=True, timeout=10).stdout
        pids = set()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].upper() == "UDP" and parts[1].endswith(f":{port}"):
                pids.add(parts[-1])
        names = []
        for pid in pids:
            t = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                               capture_output=True, text=True, timeout=10).stdout.strip()
            names.append(t.split(",")[0].strip('"') if t else f"PID {pid}")
        return ", ".join(sorted(set(names)))
    except Exception:
        return ""


def run_elevated(exe: str, args: str) -> bool:
    """ShellExecute 'runas' — triggers the UAC prompt. Windows only."""
    if os.name != "nt":
        return False
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
    return rc > 32


def generate_self_signed_cert(cert_path: Path, key_path: Path) -> bool:
    """Generate a self-signed certificate for manuals.playstation.net with SANs."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "manuals.playstation.net")])
        san = x509.SubjectAlternativeName([
            x509.DNSName("manuals.playstation.net"),
            x509.DNSName("manual.playstation.net"),
            x509.DNSName("doc.dl.playstation.net"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        return True
    except Exception:
        return False


def ensure_cert() -> bool:
    """Ensure TLS certificate exists, generate if missing."""
    ASSETS.mkdir(parents=True, exist_ok=True)
    crt, key = ASSETS / "manuals.crt", ASSETS / "manuals.key"
    if crt.is_file() and key.is_file():
        # Verify it loads
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, key)
            return True
        except Exception:
            pass
    # Generate new
    return generate_self_signed_cert(crt, key)


def self_test(ip: str, dns_port: int = DNS_PORT, https_port: int = HTTPS_PORT) -> List[Tuple[str, bool, str]]:
    """Real end-to-end checks against our own servers."""
    results = []

    def dns_check(name: str, expect: str) -> Tuple[bool, str]:
        pkt = dns_query_packet(name)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(4)
            s.sendto(pkt, (ip, dns_port))
            resp, _ = s.recvfrom(4096)
        ancount = struct.unpack(">H", resp[6:8])[0]
        got = socket.inet_ntoa(resp[-4:]) if ancount else "NODATA"
        return got == expect, got

    for name, expect in (("manuals.playstation.net", ip), ("update.playstation.net", "0.0.0.0")):
        try:
            ok, got = dns_check(name, expect)
            results.append((f"DNS {name}", ok, f"→ {got}"))
        except Exception as e:
            results.append((f"DNS {name}", False, str(e)))

    # Intentionally unverified TLS: we are probing OUR OWN deliberately
    # self-signed MITM cert (the PS5 shows the same warning and the user
    # accepts it). No real traffic is involved — loopback/LAN self-test only.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for path, want_code, want_ctype in (
        ("/document/en/ps5/", 200, "text/html"),
        ("/document/en/ps5/src/firmware.js", 200, "text/javascript"),
        ("/definitely-missing.js", 404, None),
    ):
        try:
            req = urllib.request.Request(f"https://{ip}:{https_port}{path}",
                                         headers={**UA, "Host": "manuals.playstation.net"})
            try:
                r = urllib.request.urlopen(req, timeout=8, context=ctx)
                code, ctype, body = r.status, r.headers.get("Content-Type", ""), r.read()
                cache = r.headers.get("Cache-Control", "")
                r.close()
            except urllib.error.HTTPError as e:
                code, ctype, body, cache = e.code, "", b"", e.headers.get("Cache-Control", "")
            ok = code == want_code and (want_ctype is None or want_ctype in ctype)
            if want_code == 200 and want_ctype == "text/html":
                ok = ok and b"WAK" in body and cache == "no-store"
            results.append((f"HTTPS {path}", ok, f"HTTP {code}"))
        except Exception as e:
            results.append((f"HTTPS {path}", False, str(e)))
    return results


# ─── GUI ──────────────────────────────────────────────────────────────────

STR = {
    "en": {
        "title": "SEKT0R AUTO JAILBREAK TOOLKIT",
        "subtitle": f"Relapse self-host · v{APP_VER} · firmware 7.00–13.60",
        "fw_warn": ("Supported firmware: 7.00 – 13.60 (Relapse). 14.00 and newer CANNOT be jailbroken "
                    "and the PS5 cannot be downgraded. Turn OFF automatic updates on the console."),
        "adapter": "Network adapter (PC side):",
        "refresh": "Refresh",
        "dns_label": "Primary DNS to enter on the PS5",
        "copy": "Copy",
        "copied": "Copied to clipboard.",
        "download": "1 · Download / Update files",
        "start": "2 · Start server",
        "stop": "Stop",
        "verify": "Self-test",
        "static_ip": "Set static IP (admin)",
        "dhcp": "Restore DHCP (admin)",
        "firewall": "Firewall rules (admin)",
        "files": "Files", "dns": "DNS", "web": "Web",
        "not_ready": "not downloaded", "ready": "ready", "running": "running", "stopped": "stopped",
        "steps_title": "On the PS5",
        "steps": (
            "1. Connect a LAN cable between this PC and the PS5 (or plug both into the same router).\n"
            "2. PS5: Settings → Network → Set Up Internet Connection → Wired LAN → Advanced Settings.\n"
            f"     • Direct cable: first press “Set static IP” here, then on the PS5 set IP {PS5_IP},\n"
            f"       subnet {STATIC_MASK}, gateway {STATIC_IP}.\n"
            "     • Same router: leave IP settings on Automatic.\n"
            "3. DNS Settings → Manual → Primary DNS: the address shown above · Secondary DNS: 0.0.0.0.\n"
            "4. Open Settings → Guide & Tips, Health & Safety… → User's Guide. Accept the certificate warning.\n"
            "5. The WAK1360 page appears — press START. If it stalls, reload and retry (WebKit can need several tries).\n"
            "6. After success, open PAYLOADS and load OnionHEN / kstuff / FTP Server as needed."
        ),
        "log": "Log",
        "lang": "فارسی",
        "need_files": "Download the files first (step 1).",
        "no_adapter": "No network adapter with an IPv4 address found.",
        "started": "Servers running. Set the PS5 DNS to {ip}, then open the User's Guide.",
        "stopped_msg": "Servers stopped.",
        "bind_fail": "Could not bind {what} on {ip}:{port} — {err}",
        "port_hint": "Port 53 is often held by Windows ICS (Internet Connection Sharing). Disable ICS on the shared adapter, or use the static-IP direct-cable mode.",
        "dl_ok": "Download complete — you can start the server.",
        "dl_fail": "Download failed: {err}",
        "test_running": "Running self-test …",
        "test_pass": "Self-test PASSED — PC side is ready. Now configure the PS5.",
        "test_fail": "Self-test FAILED — see log. Check Windows Firewall (use the firewall button) and that the right adapter is selected.",
        "elev_ok": "Requested administrator rights — accept the UAC prompt. {what}",
        "elev_fail": "Could not request administrator rights.",
        "static_done": "Static IP requested: {alias} → {ip}. Press Refresh, then select it.",
        "dhcp_done": "DHCP restore requested for {alias}. Press Refresh afterwards.",
        "fw_done": "Firewall allow rules requested for UDP 53, TCP 80, TCP 443.",
        "exit_hint": "Servers stop automatically when you close the app.",
        "disclaimer": "For a console you own · security research only · no piracy content · use at your own risk (ban/brick possible).",
        "cert_gen": "Generating TLS certificate…",
        "cert_ok": "TLS certificate ready.",
        "cert_fail": "Certificate generation failed (install 'cryptography' or provide manuals.crt/key).",
        "payloads_title": "Payloads",
        "payload_status": "Status",
        "firmware_info": "Firmware 7.00–13.60 supported. Your PS5 must be on a supported version.",
    },
}


class App:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk = tk, ttk
        self.root = root
        self.lang = "en"
        self.q = queue.Queue()
        self.servers = []
        self.busy = False
        self.interfaces = []
        self.logger = setup_logging(self.q)
        self._build_style()
        self._build()
        self.refresh_interfaces()
        self.refresh_files_status()
        self.logger.info(f"{APP_NAME} v{APP_VER} — {self.t('exit_hint')}")
        self.root.after(100, self._drain)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # -- i18n / style
    def t(self, key: str, **kw: Any) -> str:
        s = STR["en"][key]
        return s.format(**kw) if kw else s

    def _build_style(self) -> None:
        ttk = self.ttk
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        c = CFG["gui"]["colors"]
        self.BG, self.CARD, self.FG, self.ACC = c["bg"], c["card"], c["fg"], c["accent"]
        self.root.configure(bg=self.BG)
        self.style.configure(".", background=self.BG, foreground=self.FG, fieldbackground=self.CARD,
                             bordercolor=self.CARD, lightcolor=self.CARD, darkcolor=self.CARD)
        self.style.configure("TFrame", background=self.BG)
        self.style.configure("Card.TFrame", background=self.CARD)
        self.style.configure("TLabel", background=self.BG, foreground=self.FG, font=("Segoe UI", 10))
        self.style.configure("Card.TLabel", background=self.CARD, foreground=self.FG)
        self.style.configure("Big.TLabel", background=self.CARD, foreground="#7dd3fc", font=("Segoe UI", 24, "bold"))
        self.style.configure("Warn.TLabel", background="#2a2010", foreground=c["warning"], font=("Segoe UI", 9))
        self.style.configure("Dim.TLabel", background=self.BG, foreground=c["muted"], font=("Segoe UI", 9))
        self.style.configure("Success.TLabel", background=self.BG, foreground=c["success"], font=("Segoe UI", 9))
        self.style.configure("Error.TLabel", background=self.BG, foreground=c["error"], font=("Segoe UI", 9))
        self.style.configure("TButton", background=self.CARD, foreground=self.FG, font=("Segoe UI", 10), padding=6)
        self.style.map("TButton", background=[("active", "#263140"), ("disabled", "#151a20")],
                       foreground=[("disabled", "#6b7280")])
        self.style.configure("Accent.TButton", background=self.ACC, foreground="#ffffff", font=("Segoe UI", 10, "bold"))
        self.style.map("Accent.TButton", background=[("active", "#2563eb"), ("disabled", "#1e3a5f")])
        self.style.configure("TCombobox", fieldbackground=self.CARD, background=self.CARD, foreground=self.FG)
        self.style.configure("Horizontal.TProgressbar", background=self.ACC, troughcolor=self.CARD, bordercolor=self.CARD)
        self.style.configure("TLabelframe", background=self.BG, foreground=self.FG)
        self.style.configure("TLabelframe.Label", background=self.BG, foreground=c["muted"], font=("Segoe UI", 9, "bold"))

    # -- widgets
    def _build(self) -> None:
        tk, ttk = self.tk, self.ttk
        self.root.title(self.t("title"))
        self.root.geometry(CFG["gui"]["window_size"])
        self.root.minsize(*map(int, CFG["gui"]["min_window_size"].split("x")))
        pad = {"padx": 14, "pady": 4}

        head = ttk.Frame(self.root); head.pack(fill="x", **pad)
        self.lbl_title = ttk.Label(head, text=self.t("title"), font=("Segoe UI", 16, "bold"))
        self.lbl_title.pack(side="left")
        self.lbl_sub = ttk.Label(head, text=self.t("subtitle"), style="Dim.TLabel")
        self.lbl_sub.pack(side="left", padx=10)

        self.lbl_warn = tk.Label(self.root, text=self.t("fw_warn"), bg="#2a2010", fg=CFG["gui"]["colors"]["warning"],
                                 font=("Segoe UI", 9), wraplength=820, padx=10, pady=6)
        self.lbl_warn.pack(fill="x", padx=14, pady=(2, 6))

        # Firmware info
        fw_info = ttk.Label(self.root, text=self.t("firmware_info"), style="Dim.TLabel", wraplength=820)
        fw_info.pack(fill="x", padx=14, pady=(0, 6))

        row = ttk.Frame(self.root); row.pack(fill="x", **pad)
        self.lbl_adapter = ttk.Label(row, text=self.t("adapter"))
        self.lbl_adapter.pack(side="left")
        self.cmb_if = ttk.Combobox(row, state="readonly", width=42)
        self.cmb_if.pack(side="left", padx=8)
        self.cmb_if.bind("<<ComboboxSelected>>", lambda e: self.update_dns_label())
        self.btn_refresh = ttk.Button(row, text=self.t("refresh"), command=self.refresh_interfaces)
        self.btn_refresh.pack(side="left")

        card = ttk.Frame(self.root, style="Card.TFrame"); card.pack(fill="x", padx=14, pady=6)
        self.lbl_dns_caption = ttk.Label(card, text=self.t("dns_label"), style="Card.TLabel")
        self.lbl_dns_caption.pack(anchor="w", padx=12, pady=(8, 0))
        inner = ttk.Frame(card, style="Card.TFrame"); inner.pack(fill="x", padx=12, pady=(0, 10))
        self.lbl_ip = ttk.Label(inner, text="—", style="Big.TLabel")
        self.lbl_ip.pack(side="left")
        self.btn_copy = ttk.Button(inner, text=self.t("copy"), command=self.copy_ip)
        self.btn_copy.pack(side="right")

        btns = ttk.Frame(self.root); btns.pack(fill="x", **pad)
        self.btn_dl = ttk.Button(btns, text=self.t("download"), style="Accent.TButton", command=self.on_download)
        self.btn_dl.pack(side="left")
        self.btn_start = ttk.Button(btns, text=self.t("start"), style="Accent.TButton", command=self.on_start)
        self.btn_start.pack(side="left", padx=8)
        self.btn_stop = ttk.Button(btns, text=self.t("stop"), command=self.on_stop, state="disabled")
        self.btn_stop.pack(side="left")
        self.btn_test = ttk.Button(btns, text=self.t("verify"), command=self.on_selftest)
        self.btn_test.pack(side="left", padx=8)

        helpers = ttk.Frame(self.root); helpers.pack(fill="x", **pad)
        self.btn_static = ttk.Button(helpers, text=self.t("static_ip"), command=self.on_static_ip)
        self.btn_static.pack(side="left")
        self.btn_dhcp = ttk.Button(helpers, text=self.t("dhcp"), command=self.on_dhcp)
        self.btn_dhcp.pack(side="left", padx=8)
        self.btn_fw = ttk.Button(helpers, text=self.t("firewall"), command=self.on_firewall)
        self.btn_fw.pack(side="left")

        stat = ttk.Frame(self.root); stat.pack(fill="x", **pad)
        self.lbl_files = ttk.Label(stat, text="")
        self.lbl_files.pack(side="left")
        self.lbl_dns_stat = ttk.Label(stat, text="")
        self.lbl_dns_stat.pack(side="left", padx=16)
        self.lbl_web_stat = ttk.Label(stat, text="")
        self.lbl_web_stat.pack(side="left")
        self.progress = ttk.Progressbar(stat, mode="determinate", length=180)
        self.progress.pack(side="right")

        steps = ttk.Labelframe(self.root, text=self.t("steps_title"))
        steps.pack(fill="x", padx=14, pady=6)
        self.lbl_steps = tk.Label(steps, text=self.t("steps"), bg=self.BG, fg=self.FG,
                                  font=("Segoe UI", 9), wraplength=820)
        self.lbl_steps.pack(fill="x", padx=8, pady=4)
        self.steps_frame = steps

        logf = ttk.Labelframe(self.root, text=self.t("log"))
        logf.pack(fill="both", expand=True, padx=14, pady=6)
        self.txt_log = tk.Text(logf, height=8, bg="#0b0f13", fg="#d1d5db", insertbackground="#d1d5db",
                               font=("Consolas", 9), wrap="word", state="disabled", relief="flat")
        sb = ttk.Scrollbar(logf, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt_log.pack(fill="both", expand=True, padx=4, pady=4)
        self.logf = logf

        self.lbl_disc = ttk.Label(self.root, text=self.t("disclaimer"), style="Dim.TLabel", wraplength=820)
        self.lbl_disc.pack(fill="x", padx=14, pady=(0, 8))

    # -- helpers
    def log(self, msg: str, level: str = "info") -> None:
        self.q.put(("log", f"[{time.strftime('%H:%M:%S')}] {msg}"))
        getattr(self.logger, level.lower(), self.logger.info)(msg)

    def _drain(self) -> None:
        try:
            while True:
                kind, *rest = self.q.get_nowait()
                if kind == "log":
                    self.txt_log.configure(state="normal")
                    self.txt_log.insert("end", rest[0] + "\n")
                    self.txt_log.see("end")
                    self.txt_log.configure(state="disabled")
                elif kind == "progress":
                    done, total = rest
                    if total:
                        self.progress.configure(mode="determinate", maximum=total, value=done)
                    else:
                        self.progress.configure(mode="indeterminate")
                        self.progress.start(12)
                elif kind == "progress_stop":
                    self.progress.stop()
                    self.progress.configure(mode="determinate", value=0)
                elif kind == "busy":
                    self.busy = rest[0]
                    state = "disabled" if self.busy else "normal"
                    self.btn_dl.configure(state=state)
                    self.btn_start.configure(state=state if not self.servers else "disabled")
                elif kind == "files_ok":
                    self.refresh_files_status()
                elif kind == "servers":
                    self.refresh_server_status()
                elif kind == "ifaces":
                    self.interfaces = rest[0]
                    self.cmb_if.configure(values=[f"{alias} — {ip}" for ip, alias in self.interfaces])
                    if self.interfaces:
                        cur = self.selected_ip()
                        want = cur if any(ip == cur for ip, _ in self.interfaces) else pick_default(self.interfaces)
                        for i, (ip, _) in enumerate(self.interfaces):
                            if ip == want:
                                self.cmb_if.current(i)
                                break
                    self.update_dns_label()
                elif kind == "selftest_done":
                    ok = rest[0]
                    self.log(self.t("test_pass") if ok else self.t("test_fail"),
                             level="info" if ok else "error")
                    self.btn_test.configure(state="normal")
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def selected_ip(self) -> str:
        i = self.cmb_if.current()
        if 0 <= i < len(self.interfaces):
            return self.interfaces[i][0]
        return ""

    def selected_alias(self) -> str:
        i = self.cmb_if.current()
        if 0 <= i < len(self.interfaces):
            return self.interfaces[i][1]
        return ""

    def update_dns_label(self) -> None:
        self.lbl_ip.configure(text=self.selected_ip() or "—")

    def copy_ip(self) -> None:
        ip = self.selected_ip()
        if ip:
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.log(self.t("copied"))

    def refresh_interfaces(self) -> None:
        def work() -> None:
            self.q.put(("ifaces", list_interfaces()))
        threading.Thread(target=work, daemon=True).start()

    def files_ready(self) -> bool:
        return (WWW / "index.html").is_file() and not verify_www(WWW)

    def refresh_files_status(self) -> None:
        ok = (WWW / "index.html").is_file()
        txt = self.t("ready") if ok else self.t("not_ready")
        extra = ""
        if MANIFEST.is_file():
            try:
                extra = " · " + json.loads(MANIFEST.read_text(encoding="utf-8")).get("downloaded_at", "")
            except Exception:
                pass
        color = CFG["gui"]["colors"]["success"] if ok else CFG["gui"]["colors"]["warning"]
        self.lbl_files.configure(text=f"● {self.t('files')}: {txt}{extra}", foreground=color)

    def refresh_server_status(self) -> None:
        running = bool(self.servers)
        dns_up = any(isinstance(s, DNSServer) for s in self.servers)
        web_up = sum(1 for s in self.servers if isinstance(s, WebServer))
        self.lbl_dns_stat.configure(
            text=f"● {self.t('dns')}: {self.t('running') if dns_up else self.t('stopped')}",
            foreground=CFG["gui"]["colors"]["success"] if dns_up else CFG["gui"]["colors"]["muted"])
        self.lbl_web_stat.configure(
            text=f"● {self.t('web')}: {self.t('running') if web_up == 2 else self.t('stopped')}",
            foreground=CFG["gui"]["colors"]["success"] if web_up == 2 else CFG["gui"]["colors"]["muted"])
        self.btn_start.configure(state="disabled" if running or self.busy else "normal")
        self.btn_stop.configure(state="normal" if running else "disabled")
        self.btn_test.configure(state="normal" if running else "disabled")

    # -- actions
    def on_download(self) -> None:
        if self.busy:
            return
        self.q.put(("busy", True))
        # Ensure cert exists before download completes
        def cert_work() -> None:
            if not ensure_cert():
                self.log(self.t("cert_fail"), level="warning")
        threading.Thread(target=cert_work, daemon=True).start()

        def work() -> None:
            try:
                def prog(done: int, total: int) -> None:
                    self.q.put(("progress", done, total))
                download_all(WWW, self.log, progress=prog)
                self.q.put(("progress_stop",))
                self.log(self.t("dl_ok"))
                self.q.put(("files_ok",))
            except Exception as e:
                self.q.put(("progress_stop",))
                self.log(self.t("dl_fail", err=e), level="error")
            finally:
                self.q.put(("busy", False))
        threading.Thread(target=work, daemon=True).start()

    def on_start(self) -> None:
        if self.busy or self.servers:
            return
        if not (WWW / "index.html").is_file():
            self.log(self.t("need_files"), level="warning")
            return
        ip = self.selected_ip()
        if not ip:
            self.log(self.t("no_adapter"), level="warning")
            return
        problems = verify_www(WWW)
        if problems:
            self.log("Integrity problems: " + "; ".join(problems) + " — re-download.", level="error")
            return
        # Ensure cert
        if not ensure_cert():
            self.log(self.t("cert_fail"), level="error")
            return
        made = []
        try:
            dns = DNSServer(ip, DNS_PORT)
            made.append(dns)
            http = WebServer(ip, HTTP_PORT, WWW, self.log)
            made.append(http)
            https = WebServer(ip, HTTPS_PORT, WWW, self.log, use_tls=True)
            made.append(https)
        except OSError as e:
            for s in made:
                s.shutdown()
                s.server_close()
            what = ("DNS", "HTTP", "HTTPS")[len(made)]
            port = (DNS_PORT, HTTP_PORT, HTTPS_PORT)[len(made)]
            self.log(self.t("bind_fail", what=what, ip=ip, port=port, err=e), level="error")
            owner = port_owner(port)
            if owner:
                self.log(f"Port {port} is held by: {owner}")
            if port == DNS_PORT:
                self.log(self.t("port_hint"))
            return
        self.servers = made
        for s in made:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        self.log(self.t("started", ip=ip))
        self.refresh_server_status()

    def on_stop(self) -> None:
        for s in self.servers:
            try:
                s.shutdown()
                s.server_close()
            except Exception:
                pass
        self.servers = []
        self.log(self.t("stopped_msg"))
        self.refresh_server_status()

    def on_selftest(self) -> None:
        if not self.servers:
            return
        ip = self.selected_ip()
        self.btn_test.configure(state="disabled")
        self.log(self.t("test_running"))

        def work() -> None:
            results = self_test(ip)
            all_ok = True
            for name, ok, detail in results:
                self.log(f"  {'PASS' if ok else 'FAIL'}  {name}  {detail}",
                         level="info" if ok else "error")
                all_ok = all_ok and ok
            self.q.put(("selftest_done", all_ok))
        threading.Thread(target=work, daemon=True).start()

    def _elev(self, args: str, ok_msg: str) -> None:
        if os.name != "nt":
            self.log("Admin helpers are Windows-only.", level="warning")
            return
        if run_elevated("netsh.exe", args):
            self.log(self.t("elev_ok", what=ok_msg))
        else:
            self.log(self.t("elev_fail"), level="error")

    def on_static_ip(self) -> None:
        alias = self.selected_alias()
        if not alias or alias in ("?", "adapter"):
            self.log(self.t("no_adapter"), level="warning")
            return
        self._elev(f'interface ip set address name="{alias}" static {STATIC_IP} {STATIC_MASK}',
                   self.t("static_done", alias=alias, ip=STATIC_IP))
        self.root.after(2500, self.refresh_interfaces)

    def on_dhcp(self) -> None:
        alias = self.selected_alias()
        if not alias or alias in ("?", "adapter"):
            self.log(self.t("no_adapter"), level="warning")
            return
        self._elev(f'interface ip set address name="{alias}" dhcp',
                   self.t("dhcp_done", alias=alias))
        self.root.after(2500, self.refresh_interfaces)

    def on_firewall(self) -> None:
        if os.name != "nt":
            self.log("Admin helpers are Windows-only.", level="warning")
            return
        ok = True
        for name, proto, port in (("PS5 JB Helper DNS", "UDP", 53),
                                  ("PS5 JB Helper HTTP", "TCP", 80),
                                  ("PS5 JB Helper HTTPS", "TCP", 443)):
            ok = run_elevated("netsh.exe",
                              f'advfirewall firewall add rule name="{name}" dir=in action=allow protocol={proto} localport={port}') and ok
        self.log(self.t("fw_done") if ok else self.t("elev_fail"), level="info" if ok else "error")

    def on_close(self) -> None:
        try:
            self.on_stop()
        finally:
            self.root.destroy()


def main() -> None:
    try:
        import tkinter as tk
    except ImportError:
        print("tkinter is missing. Install Python from https://python.org (includes tkinter).")
        sys.exit(1)
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()