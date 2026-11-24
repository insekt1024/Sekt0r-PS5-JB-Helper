"""Tests for the PS5 payload manager (file manager for jailbreak payloads)."""
import json
from pathlib import Path

import pytest

from ps5_jb_helper.payloads import (
    Payload,
    PayloadList,
    PayloadManager,
    sha256_of,
)
from tests.test_ps5_jb_helper import CFG


@pytest.fixture()
def mgr(tmp_path):
    www = tmp_path / "www"
    (www / "payloads").mkdir(parents=True, exist_ok=True)
    return PayloadManager(www)


def test_manager_scans_installed(mgr, tmp_path):
    (mgr.www / "payloads" / "evil.elf").write_bytes(b"\x00" * 100)
    found = mgr.list_payloads()
    assert len(found) == 1
    assert found[0].name == "evil.elf"
    assert found[0].size == 100
    assert sha256_of(mgr.www / "payloads" / "evil.elf") is not None


def test_manager_get_missing_returns_none(mgr):
    assert mgr.get("nope.elf") is None
    assert mgr.exists("nope.elf") is False


def test_manager_lists_roundtrip(mgr, tmp_path):
    mgr.save_lists([PayloadList("hen", ["OnionHEN.elf", "ftpsrv-ps5.elf"]), PayloadList("full", [])])
    loaded = mgr.load_lists()
    assert [l.name for l in loaded] == ["hen", "full"]
    assert loaded[0].payloads == ["OnionHEN.elf", "ftpsrv-ps5.elf"]


def test_manager_ensure_skips_when_no_url(mgr, monkeypatch):
    mgr._registry = lambda: {"shadowmountplus.elf": {"group": "optional"}}  # no URL
    assert mgr.ensure(["shadowmountplus.elf"]) == []
    assert mgr.exists("shadowmountplus.elf") is False


def test_manager_ensure_installs(mgr, monkeypatch, tmp_path):
    mgr._registry = lambda: {
        "ftpsrv-ps5.elf": {"url": "https://example.test/ftpsrv.elf", "sha256": "abc", "size": 64}
    }

    def fake_pooch(url, dest, sha256, max_retries, retry_delay):
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"\0" * 64)
        return dest

    monkeypatch.setattr("ps5_jb_helper.payloads.download_pooch", fake_pooch)
    installed = mgr.ensure(["ftpsrv-ps5.elf", "missing.elf"])
    assert installed == ["ftpsrv-ps5.elf"]
    assert (mgr.www / "payloads" / "ftpsrv-ps5.elf").is_file()


def test_payload_dataclass_verified(mgr, tmp_path):
    p = Payload(name="x.elf", url="https://y", sha256="abc", size=4)
    (mgr.www / "payloads" / "x.elf").write_bytes(b"abcd")
    assert p.verified() is False  # wrong hash
    Path(mgr.www / "payloads" / "x.elf").write_bytes(b"abc" + b"d")
    # hash_of recomputes; still wrong → False
    assert p.verified() is False
