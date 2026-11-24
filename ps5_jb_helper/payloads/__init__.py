"""Payload management for the PS5 Jailbreak Helper.

A small, file-manager-style layer over the PS5 jailbreak payload set. It gives
you named *payload lists* (e.g. ``hen``, ``full``, ``lite``) and a scan/install/
verify view of what is actually on disk, so payloads can be added to lists,
installed, hash-verified, and removed again.

All downloads go through `pooch`_ (hash-verified, retryable, cached) instead of
a hand-rolled ``urllib`` loop.

.. _pooch: https://github.com/tsheo/pooch
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, MutableMapping, Optional

import pooch

from ps5_jb_helper.config import CFG
from ps5_jb_helper.utils import format_bytes

__all__ = [
    "Payload",
    "PayloadList",
    "PayloadManager",
    "PayloadError",
    "PayloadDownloadError",
    "PayloadHashError",
]

def sha256_of(path: Path) -> Optional[str]:
    """SHA-256 of a file, or None when it cannot be read."""
    try:
        return hashlib.sha256(Path(path).resolve().read_bytes()).hexdigest()
    except OSError:
        return None


logger = logging.getLogger("ps5_jb_helper.payloads")

PAYLOAD_DIRNAME = "payloads"
MANIFEST_NAME = "payload_lists.json"


class PayloadError(Exception):
    """Base error for the payload manager."""


class PayloadDownloadError(PayloadError):
    """A payload could not be downloaded (network, HTTP, retries)."""


class PayloadHashError(PayloadError):
    """SHA-256 mismatch for a downloaded payload."""


# --------------------------------------------------------------------------- #
# models
# --------------------------------------------------------------------------- #
@dataclass
class Payload:
    """One payload file known to the manager."""

    name: str
    url: str
    sha256: Optional[str] = None
    group: str = "optional"
    active: bool = False
    size: int = 0
    www_root: Optional[Path] = None

    @property
    def dest(self) -> Path:
        return (Path(self.www_root or Path(CFG.get("www_root", "."))) / PAYLOAD_DIRNAME / self.name)

    def hash_of(self) -> Optional[str]:
        try:
            return hashlib.sha256(self.dest.resolve().read_bytes()).hexdigest()
        except OSError:
            return None

    def verified(self) -> bool:
        h = self.hash_of()
        if h is None or not self.sha256:
            return False
        return h.lower() == self.sha256.lower()


@dataclass
class PayloadList:
    """A named collection of payload names."""

    name: str
    payloads: List[str] = field(default_factory=list)

    def members(self, manager: "PayloadManager") -> List[Payload]:
        return [p for p in (manager.get(p) for p in self.payloads) if p is not None]

    def add(self, name: str) -> None:
        if name not in self.payloads:
            self.payloads.append(name)

    def remove(self, name: str) -> None:
        self.payloads = [p for p in self.payloads if p != name]


# --------------------------------------------------------------------------- #
# download helper (pooch)
# --------------------------------------------------------------------------- #
def download_pooch(url: str, dest: Path, sha256: Optional[str], max_retries: int, retry_delay: float) -> Path:
    """Download *url* -> *dest* through pooch, verifying *sha256*."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".pooch-part")

    last_error: Optional[Exception] = None
    for attempt in range(1, max_retries + 1):
        try:
            pooch.retrieve(
                url,
                known_hash=sha256,
                fname=dest.name,
                path=dest.parent,
                processor=None,
                downloader=None,
                progressbar=False,
            )
            if tmp.exists():
                tmp.replace(dest)
            return dest
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < max_retries:
                import time

                time.sleep(retry_delay * attempt + 0.25)
            else:
                if tmp.exists():
                    tmp.unlink(missing_ok=True)
                raise PayloadDownloadError(f"download failed for {url}: {exc}") from exc

    raise PayloadDownloadError(f"download failed: {last_error}")


# --------------------------------------------------------------------------- #
# manager
# --------------------------------------------------------------------------- #
class PayloadManager:
    """Manages the mounted PS5 payload set on disk."""

    def __init__(self, www_root: Path, log: Optional[logging.Logger] = None):
        self.www = Path(www_root)
        self.dest_dir = self.www / PAYLOAD_DIRNAME
        self._lists_path = self.www / MANIFEST_NAME
        self.log = log or logging.getLogger("ps5_jb_helper")

    # -- registry ----------------------------------------------------------- #
    def _registry(self) -> MutableMapping[str, dict]:
        return CFG["payloads"].get("registry", {})

    # -- file manager -------------------------------------------------------- #
    def list_payloads(self) -> List[Payload]:
        if not self.dest_dir.is_dir():
            return []
        out: List[Payload] = []
        for p in sorted(self.dest_dir.iterdir()):
            if not p.is_file():
                continue
            out.append(
                Payload(
                    name=p.name,
                    url="",
                    sha256=sha256_of(p),
                    group="installed",
                    active=p.name in self._registry(),
                    size=p.stat().st_size,
                )
            )
        return out

    def get(self, name: str) -> Optional[Payload]:
        p = self.dest_dir / name
        if not p.is_file():
            return None
        return Payload(
            name=name,
            url="",
            sha256=sha256_of(p),
            group="installed",
            active=name in self._registry(),
            size=p.stat().st_size,
        )

    def exists(self, name: str) -> bool:
        return (self.dest_dir / name).is_file()

    # -- payload lists ------------------------------------------------------ --#
    def load_lists(self) -> List[PayloadList]:
        if self._lists_path.is_file():
            try:
                data = json.loads(self._lists_path.read_text(encoding="utf-8"))
                return [PayloadList(name=k, payloads=v) for k, v in data.items()]
            except (ValueError, OSError) as exc:
                self.log.warning("Could not read payload lists manifest: %s", exc)
        return [PayloadList("hen", []), PayloadList("full", [])]

    def save_lists(self, lists: Iterable[PayloadList]) -> None:
        data = {l.name: list(l.payloads) for l in lists}
        self._lists_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def active_list(self, name: str) -> Optional[PayloadList]:
        for l in self.load_lists():
            if l.name == name:
                return l
        return None

    # -- install ------------------------------------------------------------ --#
    def ensure(self, names=None, progress=None) -> List[str]:
        """Download every payload that is missing from disk.

        ``names`` limits the set to install (active payload lists if omitted).
        Returns the list of successfully installed payloads.
        """
        self.dest_dir.mkdir(parents=True, exist_ok=True)
        to_download = set(names) if names is not None else {p for l in self.load_lists() for p in l.payloads}
        installed: List[str] = []
        for name in sorted(to_download):
            if self.exists(name):
                continue
            meta = self._registry().get(name)
            if not meta or not meta.get("url"):
                self.log.warning("No URL registered for payload %r", name)
                continue
            payload = Payload(
                name=name,
                url=meta["url"],
                sha256=meta.get("sha256"),
                group=meta.get("group", "optional"),
                size=meta.get("size", 0),
                www_root=self.www,
            )
            download_pooch(payload.url, payload.dest, payload.sha256, CFG["download"]["max_retries"], CFG["download"]["retry_delay"])
            self.log.info("Installed payload %r", name)
            installed.append(name)
        return installed

    # -- remove ------------------------------------------------------------- --#
    def remove(self, name: str) -> bool:
        p = self.dest_dir / name
        if not p.is_file():
            return False
        p.unlink()
        reg = self._registry()
        reg.pop(name, None)
        self.save_lists(self.load_lists())
        return True
