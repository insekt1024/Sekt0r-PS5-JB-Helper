"""Automated tests for ps5_jb_helper.

Run:  python -m pytest tests/ -q
"""
import hashlib
import socket
import struct
import threading
import tempfile
import shutil
from pathlib import Path

import pytest
from ps5_jb_helper.config import CFG, DEFAULT_CONFIG, load_config, save_config, validate_config
from ps5_jb_helper.dns import DNSServer, build_query_packet, QTYPE_A, QTYPE_AAAA
from ps5_jb_helper.download import download_file, verify_sha256
from ps5_jb_helper.http import DEEP_ASSET_RE, map_path
from ps5_jb_helper.utils import compute_required_files, verify_www

WWW = Path(__file__).resolve().parents[1] / "www"


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def test_default_config_shape():
    payloads = DEFAULT_CONFIG["payloads"]
    assert "required" in payloads
    assert "optional" in payloads
    assert payloads["required"] and payloads["optional"]


def test_validate_config():
    assert validate_config(DEFAULT_CONFIG) == (True, [])


def test_validate_config_rejects_firmware_version():
    cfg = dict(DEFAULT_CONFIG)
    del cfg["network"]["guide_domains"]
    is_valid, errors = validate_config(cfg)
    assert is_valid is False
    assert errors


def test_config_roundtrip(tmp_path):
    p = tmp_path / "config.json"
    save_config(DEFAULT_CONFIG, p)
    loaded = load_config(p)
    assert loaded["upstream"]["host_repo"] == "arg0WAK/WAK1360-Relapse"


# --------------------------------------------------------------------------- #
# dns (pure respond logic)
# --------------------------------------------------------------------------- #
@pytest.fixture()
def dns_server():
    ip = "192.168.100.1"
    guide = ("manuals.playstation.net", "manual.playstation.net", "doc.dl.playstation.net")
    block = ("update.playstation.net",)
    up = ("1.1.1.1", "8.8.8.8")
    import socketserver
    from unittest.mock import patch

    def _mock_init(self, server_address, RequestHandlerClass):
        self.server_address = server_address
        self.RequestHandlerClass = RequestHandlerClass
        self.socket = None
        self.target_ip = ip
        self.guide_domains = guide
        self.block_domains = block
        self.upstream_dns = up
        self._cache = None
        self._forward_lock = threading.Lock()

    with patch.object(socketserver.UDPServer, "__init__", _mock_init):
        srv = DNSServer(ip, 53, guide, block, up)
        # Unrelated domains are forwarded to upstream, not answered locally.
        srv._forward_query = lambda data: None
    return srv


def test_dns_guide_a(dns_server):
    resp = dns_server.respond(build_query_packet("manuals.playstation.net", QTYPE_A))
    assert resp is not None
    assert socket.inet_ntoa(resp[-4:]) == "192.168.100.1"
    assert struct.unpack(">H", resp[6:8])[0] == 1


def test_dns_guide_subdomain(dns_server):
    resp = dns_server.respond(build_query_packet("sub.manual.playstation.net", QTYPE_A))
    assert resp is not None
    assert socket.inet_ntoa(resp[-4:]) == "192.168.100.1"


def test_dns_aaaa_nodata(dns_server):
    resp = dns_server.respond(build_query_packet("doc.dl.playstation.net", QTYPE_AAAA))
    assert resp is not None
    assert struct.unpack(">H", resp[6:8])[0] == 0


def test_dns_block_a(dns_server):
    resp = dns_server.respond(build_query_packet("update.playstation.net", QTYPE_A))
    assert resp is not None
    assert socket.inet_ntoa(resp[-4:]) == "0.0.0.0"


def test_dns_unrelated_forward(dns_server):
    assert dns_server.respond(build_query_packet("example.com", QTYPE_A)) is None


def test_dns_short_packet_ignored(dns_server):
    assert dns_server.respond(b"\x00" * 5) is None


# --------------------------------------------------------------------------- #
# http path mapping
# --------------------------------------------------------------------------- #
@pytest.fixture()
def www_tree():
    """A complete, self-consistent overlay tree (passes verify_www)."""
    tmp = Path(tempfile.mkdtemp(prefix="t-http-"))
    def write(rel: str, content: str = ""):
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    index = (
        "<html><head><base href=\"/\">"
        '<script src="src/helper.js"></script>'
        '<script src="src/force-ready.js"></script>'
        '<link rel="stylesheet" href="assets/index.css"></head>'
        "<body>WAK</body></html>"
    )
    write("index.html", index)
    write("src/helper.js", "//helper")
    write("src/force-ready.js", "//force-ready")
    write("assets/index.css", "body{}")
    write("src/firmware.js", "//fw")
    for p in CFG["payloads"]["required"]:
        write(f"payloads/{p}", "")
    write("payloads/payloads.json", "{}")
    write("offsets/13.60.js", "()")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.parametrize(
    "url,expected_rel,expected_kind",
    [
        ("/document/en/ps5/", "index.html", "spa"),
        ("/document/en/ps5/src/firmware.js", "src/firmware.js", "file"),
        ("/document/fr/ps5/sub/assets/index.css", "assets/index.css", "file"),
        ("/src/firmware.js", "src/firmware.js", "file"),
        ("/missing.js", None, "404"),
        ("/missing.css", None, "404"),
        ("/../../secret.txt", None, "404"),
        ("/%2e%2e/secret.txt", None, "404"),
        ("/index.html", "index.html", "file"),
    ],
)
def test_map_path(www_tree, url, expected_rel, expected_kind):
    f, m = map_path(url, www_tree)
    if expected_kind == "404":
        assert m == "404"
        assert f is None
    else:
        assert m == expected_kind
        assert f is not None
        assert f.resolve().relative_to(www_tree.resolve()).as_posix() == expected_rel


def test_deep_asset_regex():
    assert DEEP_ASSET_RE.match("/document/en/ps5/src/firmware.js")
    assert DEEP_ASSET_RE.match("/document/fr/ps5/sub/assets/index.css")
    assert DEEP_ASSET_RE.match("/document/en/ps5/../../etc/passwd") is None


# --------------------------------------------------------------------------- #
# utils
# --------------------------------------------------------------------------- #
def test_verify_www_flags_incomplete_tree(tmp_path):
    (tmp_path / "index.html").write_text("<html>WAK</html>")
    problems = verify_www(tmp_path, compute_required_files(CFG))
    assert problems


def test_verify_www_clean_full_tree(www_tree):
    problems = verify_www(www_tree, compute_required_files(CFG))
    assert problems == []


# --------------------------------------------------------------------------- #
# download
# --------------------------------------------------------------------------- #
def test_verify_sha256(tmp_path):
    data = b"\x00\x01\x02\x03" * 100
    dest = tmp_path / "in.bin"
    dest.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert verify_sha256(dest, expected)


def test_download_file_from_local(tmp_path):
    data = b"\x00\x01\x02\x03" * 100
    source = tmp_path / "src.bin"
    source.write_bytes(data)
    dest = tmp_path / "out.bin"
    digest = download_file("file://" + str(source), dest)
    assert digest.lower() == hashlib.sha256(data).hexdigest()
    assert dest.read_bytes() == data


# --------------------------------------------------------------------------- #
# gui smoke (tkinter) -- skipped when no display is available
# --------------------------------------------------------------------------- #
def test_gui_smoke():
    try:
        import tkinter as tk
    except Exception:
        pytest.skip("no tkinter display")

    from ps5_jb_helper_main import App

    root = tk.Tk()
    try:
        a = App(root)
        root.update()
        assert a.lbl_ip is not None and a.cmb_if is not None
        assert isinstance(a.interfaces, list)
        if a.interfaces:
            assert a.selected_ip()
        a.toggle_lang()
        root.update()
        assert a.lang == "fa"
        a.toggle_lang()
        root.update()
        assert a.lang == "en"
        a.log("test log line")
        a._drain()
        assert "test log line" in a.txt_log.get("1.0", "end")
    finally:
        root.destroy()


# --------------------------------------------------------------------------- #
# live end-to-end -- skip by default (needs network + ports; run with --live)
# --------------------------------------------------------------------------- #
@pytest.mark.skip(reason="offline unit suite; requires network/ports; run with --live")
def test_live():
    from ps5_jb_helper.orchestrator import download_all
    from ps5_jb_helper import MANIFEST

    logs = []
    download_all(WWW, lambda m, level="info": logs.append(m), config=CFG)
    assert (WWW / "index.html").is_file()
    assert verify_www(WWW, compute_required_files(CFG)) == []
    assert MANIFEST.is_file()
