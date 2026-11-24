#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runnable checks for ps5_jb_helper.
  python test_app.py          offline unit checks + GUI smoke
  python test_app.py --live   + real GitHub download + live DNS/HTTP/HTTPS end-to-end
"""
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
import socketserver

# Import from new modular structure
from ps5_jb_helper.dns import DNSServer, build_query_packet, QTYPE_A, QTYPE_AAAA
from ps5_jb_helper.http import map_path, WebServer
from ps5_jb_helper.utils import verify_www
from ps5_jb_helper.orchestrator import download_all
from ps5_jb_helper.config import CFG
from ps5_jb_helper.selftest import run_self_test
from ps5_jb_helper import WWW, MANIFEST, FTPSRV_SHA256, REQUIRED_FILES

PASS = 0


def check(name, cond, detail=""):
    global PASS
    if not cond:
        print(f"FAIL  {name}  {detail}")
        sys.exit(1)
    PASS += 1
    print(f"ok    {name}" + (f"  ({detail})" if detail else ""))


def unit_dns():
    ip = "192.168.100.1"
    guide_domains = tuple(CFG["network"]["guide_domains"])
    block_domains = tuple(CFG["network"]["block_domains"])
    upstream_dns = tuple(CFG["network"]["upstream_dns"])

    # Create server without binding (for testing respond logic only)
    import socketserver
    original_init = socketserver.UDPServer.__init__
    
    def mock_init(self, server_address, RequestHandlerClass):
        self.server_address = server_address
        self.RequestHandlerClass = RequestHandlerClass
        self.socket = None
        self.target_ip = ip
        self.guide_domains = guide_domains
        self.block_domains = block_domains
        self.upstream_dns = upstream_dns
        self._cache = None
        self._forward_lock = threading.Lock()
    
    socketserver.UDPServer.__init__ = mock_init
    
    try:
        dns = DNSServer(ip, 53, guide_domains, block_domains, upstream_dns)
        # Mock _forward_query to return None for unrelated domains
        dns._forward_query = lambda data: None
    finally:
        socketserver.UDPServer.__init__ = original_init

    # Test guide domain A record
    pkt = build_query_packet("manuals.playstation.net")
    r = dns.respond(pkt)
    check("dns guide A", r is not None and socket.inet_ntoa(r[-4:]) == ip and struct.unpack(">H", r[6:8])[0] == 1)

    # Test guide subdomain
    pkt = build_query_packet("sub.manual.playstation.net")
    r = dns.respond(pkt)
    check("dns guide subdomain A", r is not None and socket.inet_ntoa(r[-4:]) == ip)

    # Test guide domain AAAA -> NODATA
    pkt = build_query_packet("doc.dl.playstation.net", QTYPE_AAAA)
    r = dns.respond(pkt)
    check("dns guide AAAA nodata", r is not None and struct.unpack(">H", r[6:8])[0] == 0)

    # Test block domain A -> 0.0.0.0
    pkt = build_query_packet("update.playstation.net")
    r = dns.respond(pkt)
    check("dns block A", r is not None and socket.inet_ntoa(r[-4:]) == "0.0.0.0")

    # Test block subdomain
    pkt = build_query_packet("x.sonyentertainmentnetwork.com")
    r = dns.respond(pkt)
    check("dns block subdomain", r is not None and socket.inet_ntoa(r[-4:]) == "0.0.0.0")

    # Test unrelated domain -> forward (returns None in test since no upstream)
    pkt = build_query_packet("example.com")
    r = dns.respond(pkt)
    check("dns unrelated not answered locally", r is None)

    # Test short packet ignored
    r = dns.respond(b"\x00" * 5)
    check("dns short packet ignored", r is None)


def unit_paths():
    tmp = Path(tempfile.mkdtemp(prefix="ps5jb-test-"))
    try:
        (tmp / "src").mkdir()
        (tmp / "assets").mkdir()
        (tmp / "index.html").write_text("<html>WAK</html>")
        (tmp / "src" / "firmware.js").write_text("//fw")
        (tmp / "assets" / "index.css").write_text("body{}")
        f, m = map_path("/document/en/ps5/", tmp)
        check("path deep guide -> spa", m == "spa" and f == tmp / "index.html")
        f, m = map_path("/document/en/ps5/src/firmware.js", tmp)
        check("path deep asset rewrite", m == "file" and f == tmp / "src" / "firmware.js")
        f, m = map_path("/document/fr/ps5/sub/assets/index.css", tmp)
        check("path deeper asset rewrite", m == "file" and f == tmp / "assets" / "index.css")
        f, m = map_path("/src/firmware.js", tmp)
        check("path root asset", m == "file" and f == tmp / "src" / "firmware.js")
        f, m = map_path("/missing.js", tmp)
        check("path missing js -> 404 (no SPA fallback)", m == "404")
        f, m = map_path("/missing.css", tmp)
        check("path missing css -> 404", m == "404")
        f, m = map_path("/../../secret.txt", tmp)
        check("path traversal blocked", m == "404")
        f, m = map_path("/%2e%2e/secret.txt", tmp)
        check("path encoded traversal blocked", m == "404")
        f, m = map_path("/index.html", tmp)
        check("path explicit index", m == "file" and f == tmp / "index.html")
        problems = verify_www(tmp, REQUIRED_FILES)
        check("verify_www flags incomplete tree", len(problems) > 0, f"{len(problems)} problems")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def gui_smoke():
    import tkinter as tk
    from ps5_jb_helper_main import App
    root = tk.Tk()
    try:
        a = App(root)
        root.update()
        check("gui builds", a.lbl_ip is not None and a.cmb_if is not None)
        # In sandbox there may be no adapters — that's OK, code handles it
        check("gui interfaces enumerated", isinstance(a.interfaces, list), f"{len(a.interfaces)} adapters")
        if a.interfaces:
            check("gui default ip picked", bool(a.selected_ip()), a.selected_ip())
        a.toggle_lang()
        root.update()
        check("gui language toggle fa", a.lang == "fa" and "جیلبریک" in a.lbl_title.cget("text"))
        a.toggle_lang()
        root.update()
        check("gui language toggle en", a.lang == "en")
        a.log("test log line")
        a._drain()
        check("gui log drains", "test log line" in a.txt_log.get("1.0", "end"))
    finally:
        root.destroy()


def live():
    print("--- live: real download from GitHub ---")
    logs = []
    download_all(WWW, lambda m, level="info": logs.append(m), config=CFG)
    check("download completed", (WWW / "index.html").is_file())
    check("integrity verify_www clean", verify_www(WWW, REQUIRED_FILES) == [], str(verify_www(WWW, REQUIRED_FILES)))
    check("manifest written", MANIFEST.is_file())
    import hashlib
    got = hashlib.sha256((WWW / "payloads" / "ftpsrv-ps5.elf").read_bytes()).hexdigest()
    check("ftpsrv sha256", got == FTPSRV_SHA256, got[:16] + "…")
    idx = (WWW / "index.html").read_text(encoding="utf-8")
    check("overlay applied", 'base href="/"' in idx and "force-ready.js" in idx and "?v=4" in idx)

    print("--- live: DNS + HTTP + HTTPS on loopback, real ports ---")
    ip = "127.0.0.1"
    # Use non-privileged ports for testing (5353, 8080, 8443)
    TEST_DNS_PORT = 5353
    TEST_HTTP_PORT = 8080
    TEST_HTTPS_PORT = 8443
    servers = []
    try:
        dns = DNSServer(ip, TEST_DNS_PORT, CFG["network"]["guide_domains"], CFG["network"]["block_domains"], CFG["network"]["upstream_dns"])
        servers.append(dns)
        http = WebServer(ip, TEST_HTTP_PORT, WWW, lambda m, level="info": None)
        servers.append(http)
        from ps5_jb_helper.cert import get_cert_paths
        crt_path, key_path = get_cert_paths(Path("assets"))
        https = WebServer(ip, TEST_HTTPS_PORT, WWW, lambda m, level="info": None, use_tls=True, cert_path=crt_path, key_path=key_path)
        servers.append(https)
        for s in servers:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        time.sleep(0.3)
        # Test DNS directly
        def dns_q(name, qt=1):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(build_query_packet(name, qt), (ip, TEST_DNS_PORT))
            r, _ = s.recvfrom(4096)
            s.close()
            anc = struct.unpack(">H", r[6:8])[0]
            return anc, socket.inet_ntoa(r[-4:]) if anc else None
        anc, got = dns_q("manuals.playstation.net")
        check("selftest DNS manuals.playstation.net", anc == 1 and got == ip, f"anc={anc} got={got}")
        anc, got = dns_q("doc.dl.playstation.net", QTYPE_AAAA)
        check("selftest DNS doc.dl.playstation.net AAAA", anc == 0, f"anc={anc}")
        anc, got = dns_q("update.playstation.net")
        check("selftest DNS update.playstation.net", anc == 1 and got == "0.0.0.0", f"anc={anc} got={got}")
        # HTTP/HTTPS tests
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(f"https://{ip}:{TEST_HTTPS_PORT}/document/en/ps5/", headers={"Host": "manuals.playstation.net", "User-Agent": "x"})
        r = urllib.request.urlopen(req, timeout=8, context=ctx)
        body = r.read()
        r.close()
        check("selftest HTTPS guide", r.status == 200 and b"WAK" in body and r.headers.get("Cache-Control") == "no-store", f"code={r.status}")
        req2 = urllib.request.Request(f"http://{ip}:{TEST_HTTP_PORT}/document/en/ps5/src/firmware.js")
        r2 = urllib.request.urlopen(req2, timeout=8)
        b2 = r2.read()
        r2.close()
        check("selftest HTTP firmware.js", r2.status == 200 and len(b2) > 0, f"code={r2.status} len={len(b2)}")
        try:
            urllib.request.urlopen(urllib.request.Request(f"http://{ip}:{TEST_HTTP_PORT}/nope.js"), timeout=5)
        except urllib.error.HTTPError as e:
            check("selftest HTTP missing", e.code == 404, f"code={e.code}")
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()


if __name__ == "__main__":
    unit_dns()
    unit_paths()
    gui_smoke()
    if "--live" in sys.argv:
        live()
    print(f"\nALL {PASS} CHECKS PASSED")