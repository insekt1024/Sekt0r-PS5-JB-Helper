"""Utility functions for PS5 Jailbreak Helper."""
import hashlib
import json
import logging
import queue
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable


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


def setup_logging(log_queue: queue.Queue, config: Dict[str, Any], log_file: Path) -> logging.Logger:
    """Configure application logging."""
    logger = logging.getLogger("ps5_jb_helper")
    logger.setLevel(getattr(logging, config.get("logging", {}).get("level", "INFO").upper(), logging.INFO))
    logger.handlers.clear()

    # File handler
    fh = logging.FileHandler(log_file, encoding="utf-8")
    log_fmt = config.get("logging", {}).get("format", "[%(asctime)s] %(levelname)s: %(message)s")
    fh.setFormatter(logging.Formatter(log_fmt))
    logger.addHandler(fh)

    # Queue handler for GUI
    qh = QueueHandler(log_queue)
    qh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", "%H:%M:%S"))
    logger.addHandler(qh)

    return logger


def verify_www(www_root: Path, required_files: List[str]) -> List[str]:
    """Integrity checks mirroring the upstream self-host kit's sanity checks."""
    problems = []

    for rel in required_files:
        if not (www_root / rel).is_file():
            problems.append(f"missing {rel}")

    index_path = www_root / "index.html"
    if index_path.is_file():
        idx = index_path.read_text(encoding="utf-8", errors="replace")
        if 'base href="/"' not in idx:
            problems.append("overlay index.html not applied (no <base href>)")
        if "force-ready.js" not in idx:
            problems.append("overlay index.html missing force-ready.js")

        # Every local asset referenced by index.html must exist
        for ref in re.findall(r'(?:src|href)="([^"]+)"', idx):
            ref = ref.split("?", 1)[0]
            if ref.startswith(("http:", "https:", "data:", "#")) or not ref:
                continue
            rel = ref.lstrip("./").lstrip("/")
            if not rel or rel == ".":
                continue
            if not (www_root / rel).is_file():
                problems.append(f"index.html references missing file: {ref}")

    return problems


def compute_required_files(config: Dict[str, Any]) -> List[str]:
    """Compute required files list from config."""
    required = [
        "index.html",
        "src/firmware.js",
        "src/helper.js",
        "src/force-ready.js",
        "assets/index.css",
        "payloads/payloads.json",
    ]
    required.extend(f"payloads/{p}" for p in config.get("payloads", {}).get("required", []))
    required.append("offsets/13.60.js")  # Representative offset file
    return required


def create_manifest(
    www_root: Path,
    manifest_path: Path,
    config: Dict[str, Any],
    ftpsrv_sha256: str,
) -> None:
    """Create manifest.json with download metadata."""
    manifest_data = {
        "host_repo": config["upstream"]["host_repo"],
        "host_ref": config["upstream"]["host_ref"],
        "overlay": f"{config['upstream']['overlay_repo']}@{config['upstream']['overlay_branch']}",
        "ftpsrv": "v0.21.1",
        "ftpsrv_sha256": ftpsrv_sha256,
        "downloaded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")


def read_manifest(manifest_path: Path) -> Optional[Dict[str, Any]]:
    """Read manifest.json if it exists."""
    if manifest_path.is_file():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def format_bytes(bytes_val: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_val < 1024:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.1f} TB"


def format_duration(seconds: float) -> str:
    """Format duration as human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"


class ProgressTracker:
    """Track progress across multiple downloads."""

    def __init__(self, total_files: int, callback: Optional[Callable[[str, int, int], None]] = None):
        self.total_files = total_files
        self.completed_files = 0
        self.current_file = ""
        self.callback = callback
        self._start_time = time.time()

    def start_file(self, filename: str) -> None:
        self.current_file = filename

    def update(self, done: int, total: int) -> None:
        if self.callback:
            self.callback(self.current_file, done, total)

    def finish_file(self) -> None:
        self.completed_files += 1

    def get_overall_progress(self) -> tuple[int, int]:
        return self.completed_files, self.total_files

    def elapsed_time(self) -> float:
        return time.time() - self._start_time