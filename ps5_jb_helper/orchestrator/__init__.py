"""Main orchestrator for downloading and preparing exploit files."""
import hashlib
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional

from ps5_jb_helper.config import load_config, DEFAULT_CONFIG
from ps5_jb_helper.download import download_file, download_files_parallel, DownloadError
from ps5_jb_helper.cert import ensure_cert, get_cert_paths
from ps5_jb_helper.utils import (
    verify_www, compute_required_files, create_manifest, ProgressTracker
)


def download_all(
    www_root: Path,
    log_func: Callable[[str, str], None],
    progress: Optional[Callable[[int, int], None]] = None,
    config: Optional[dict] = None,
) -> bool:
    """
    Fetch pinned host page + overlay + FTP payload into a temp dir, verify,
    then swap into place. Old www survives any failure.
    """
    if config is None:
        config = load_config(www_root.parent / "config.json")

    www_root = Path(www_root)
    staging = www_root.with_name("www_new")

    # Clean up any previous staging
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    try:
        # Ensure cert exists before download completes
        cert_thread = None

        # Download host page
        host_repo = config["upstream"]["host_repo"]
        host_ref = config["upstream"]["host_ref"]
        host_zip = f"https://codeload.github.com/{host_repo}/zip/{host_ref}"

        log_func(f"Downloading host page {host_repo}@{host_ref[:7]} …")
        zip_path = staging / "host.zip"
        download_file(host_zip, zip_path, progress=progress)

        log_func("Extracting …")
        with ThreadPoolExecutor(max_workers=1) as executor:
            # Extract in background
            future = executor.submit(_extract_zip, zip_path, staging)
            extracted_root = future.result()

        zip_path.unlink()
        _move_extracted_files(extracted_root, staging)
        shutil.rmtree(staging / "unzip", ignore_errors=True)

        # Apply self-host overlay
        log_func("Applying self-host overlay (cache-bust, UA fixes, deep paths) …")
        _download_overlay_files(staging, config, log_func)

        # Download FTP payload
        log_func("Downloading FTP payload (ftpsrv v0.21.1) …")
        ftpsrv_url = config["upstream"]["ftpsrv_url"]
        ftpsrv_sha256 = config["upstream"]["ftpsrv_sha256"]
        download_file(
            ftpsrv_url,
            staging / "payloads" / "ftpsrv-ps5.elf",
            sha256=ftpsrv_sha256,
            progress=progress,
        )
        log_func("  + payloads/ftpsrv-ps5.elf (SHA-256 verified)")

        # Verify integrity
        required_files = compute_required_files(config)
        problems = verify_www(staging, required_files)
        if problems:
            raise DownloadError("Integrity check failed:\n  " + "\n  ".join(problems))

        # Atomic swap
        if www_root.exists():
            shutil.rmtree(www_root)
        staging.replace(www_root)

        # Create manifest
        create_manifest(www_root, www_root.parent / "manifest.json", config, ftpsrv_sha256)

        log_func("Files ready. Integrity checks passed.")
        return True

    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _extract_zip(zip_path: Path, staging: Path) -> Path:
    """Extract ZIP file and return the root directory."""
    import zipfile
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(staging / "unzip")
    roots = [p for p in (staging / "unzip").iterdir() if p.is_dir() and (p / "index.html").is_file()]
    if len(roots) != 1:
        raise DownloadError("Unexpected archive layout (no single index.html root)")
    return roots[0]


def _move_extracted_files(extracted_root: Path, staging: Path) -> None:
    """Move extracted files to staging root."""
    for item in extracted_root.iterdir():
        shutil.move(str(item), staging / item.name)


def _download_overlay_files(staging: Path, config: dict, log_func: Callable[[str, str], None]) -> None:
    """Download and apply overlay files."""
    overlay_raw = f"https://raw.githubusercontent.com/{config['upstream']['overlay_repo']}/{config['upstream']['overlay_branch']}/overlay/"
    overlay_files = ["index.html", "src/firmware.js", "src/helper.js", "src/force-ready.js"]
    payloads_json = "payloads.json"

    for rel in overlay_files:
        download_file(overlay_raw + rel, staging / rel)
        log_func(f"  + {rel}")

    download_file(overlay_raw + payloads_json, staging / "payloads" / "payloads.json")
    log_func("  + payloads/payloads.json")


def download_payloads_parallel(
    www_root: Path,
    config: dict,
    log_func: Callable[[str, str], None],
    progress: Optional[Callable[[str, int, int], None]] = None,
) -> Dict[str, str]:
    """Download optional payloads in parallel."""
    optional = config.get("payloads", {}).get("optional", [])
    if not optional:
        return {}

    urls = {}
    sha256_map = {}
    base_url = "https://github.com/ps5-payload-dev/payloads/releases/download/"

    # Note: In practice, you'd have a manifest with URLs and hashes
    # For now, we skip optional payloads as they don't have fixed URLs/hashes
    log_func("Optional payloads not configured for auto-download")
    return {}


def check_updates(config: dict) -> Dict[str, bool]:
    """Check for updates to upstream sources. Returns dict of {source: has_update}."""
    # This would require GitHub API calls to check latest commits/releases
    # For now, return empty - can be implemented later
    return {}