"""Self-test module for PS5 Jailbreak Helper."""
import socket
import ssl
import struct
import urllib.error
import urllib.request
from typing import Callable, List, Tuple

from ps5_jb_helper.dns import build_query_packet, QTYPE_A, QTYPE_AAAA


def self_test(
    ip: str,
    dns_port: int = 53,
    http_port: int = 80,
    https_port: int = 443,
    guide_domains: tuple = (),
    block_domains: tuple = (),
) -> List[Tuple[str, bool, str]]:
    """
    Real end-to-end checks against our own servers.
    Returns list of (test_name, passed, detail).
    """
    results = []

    def dns_check(name: str, expect: str, qtype: int = QTYPE_A) -> Tuple[bool, str]:
        pkt = build_query_packet(name, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(4)
            s.sendto(pkt, (ip, dns_port))
            resp, _ = s.recvfrom(4096)
        ancount = struct.unpack(">H", resp[6:8])[0]
        got = socket.inet_ntoa(resp[-4:]) if ancount else "NODATA"
        return got == expect, got

    # DNS tests
    for name, expect in (
        ("manuals.playstation.net", ip),
        ("update.playstation.net", "0.0.0.0"),
    ):
        try:
            ok, got = dns_check(name, expect)
            results.append((f"DNS {name}", ok, f"→ {got}"))
        except Exception as e:
            results.append((f"DNS {name}", False, str(e)))

    # AAAA test for guide domain (should return NODATA)
    if guide_domains:
        try:
            ok, got = dns_check(guide_domains[0], "NODATA", QTYPE_AAAA)
            results.append((f"DNS {guide_domains[0]} AAAA", ok, f"→ {got}"))
        except Exception as e:
            results.append((f"DNS {guide_domains[0]} AAAA", False, str(e)))

    # HTTP/HTTPS tests
    # Intentionally unverified TLS: we are probing OUR OWN deliberately
    # self-signed MITM cert (the PS5 shows the same warning and the user
    # accepts it). No real traffic is involved — loopback/LAN self-test only.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    test_cases = [
        (f"https://{ip}:{https_port}/document/en/ps5/", 200, "text/html", True),
        (f"https://{ip}:{https_port}/document/en/ps5/src/firmware.js", 200, "text/javascript", False),
        (f"https://{ip}:{https_port}/definitely-missing.js", 404, None, False),
    ]

    for path, want_code, want_ctype, check_wak in test_cases:
        try:
            req = urllib.request.Request(
                path,
                headers={"Host": "manuals.playstation.net", "User-Agent": "ps5-jb-helper/1.1.0"}
            )
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


def run_self_test(
    ip: str,
    config: dict,
    log_func: Callable[[str, str], None],
) -> bool:
    """Run self-test and log results. Returns True if all tests pass."""
    guide_domains = tuple(config["network"]["guide_domains"])
    block_domains = tuple(config["network"]["block_domains"])

    dns_port = config["network"]["dns_port"]
    http_port = config["network"]["http_port"]
    https_port = config["network"]["https_port"]

    log_func("Running self-test …")
    results = self_test(ip, dns_port, http_port, https_port, guide_domains, block_domains)

    all_ok = True
    for name, ok, detail in results:
        log_func(f"  {'PASS' if ok else 'FAIL'}  {name}  {detail}", level="info" if ok else "error")
        all_ok = all_ok and ok

    return all_ok