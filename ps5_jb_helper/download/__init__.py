"""Download module for PS5 Jailbreak Helper."""
import hashlib
import shutil
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union
import time
import random


# User agent for downloads
USER_AGENT = "ps5-jb-helper/1.1.0"

DEFAULT_TIMEOUT = 60
DEFAULT_CHUNK_SIZE = 65536
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 2


class DownloadError(Exception):
    """Download-related errors."""
    pass


def http_get(url: str, timeout: int = DEFAULT_TIMEOUT) -> urllib.request.urlopen:
    """Perform HTTP GET request with custom user agent."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def download_file(
    url: str,
    dest: Union[str, Path],
    progress: Optional[Callable[[int, int], None]] = None,
    sha256: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY,
) -> str:
    """
    Download a file with retries, progress callback, and optional SHA-256 verification.
    Returns the SHA-256 hash of the downloaded file.
    """
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")

    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            h = hashlib.sha256()
            with http_get(url, timeout=timeout) as r, open(tmp, "wb") as f:
                total = int(r.headers.get("Content-Length") or 0)
                done = 0
                while True:
                    chunk = r.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    h.update(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, total)

            # Verify SHA-256 if provided
            if sha256 and h.hexdigest().lower() != sha256.lower():
                tmp.unlink(missing_ok=True)
                raise DownloadError(
                    f"SHA-256 mismatch for {url}\n expected {sha256}\n got      {h.hexdigest()}"
                )

            # Atomic replace
            tmp.replace(dest)
            return h.hexdigest()

        except Exception as e:
            last_error = e
            tmp.unlink(missing_ok=True)

            if attempt < max_retries:
                # Exponential backoff with jitter
                delay = retry_delay * attempt + random.uniform(0, 0.5)
                time.sleep(delay)
            else:
                raise DownloadError(f"Download failed after {max_retries} attempts: {last_error}") from last_error

    raise DownloadError(f"Download failed: {last_error}")  # Should not reach here


def download_files_parallel(
    urls: Dict[str, str],
    dest_dir: Path,
    progress: Optional[Callable[[str, int, int], None]] = None,
    sha256_map: Optional[Dict[str, str]] = None,
    max_workers: int = 4,
    **download_kwargs,
) -> Dict[str, str]:
    """
    Download multiple files in parallel.
    urls: {relative_path: url}
    Returns {relative_path: sha256}
    """
    results = {}
    errors = {}

    def download_one(rel_path: str, url: str) -> tuple[str, str]:
        dest = dest_dir / rel_path
        sha = download_file(
            url,
            dest,
            progress=lambda d, t: progress(rel_path, d, t) if progress else None,
            sha256=sha256_map.get(rel_path) if sha256_map else None,
            **download_kwargs,
        )
        return rel_path, sha

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {
            executor.submit(download_one, rel, url): rel
            for rel, url in urls.items()
        }

        for future in as_completed(future_to_path):
            rel = future_to_path[future]
            try:
                rel_path, sha = future.result()
                results[rel_path] = sha
            except Exception as e:
                errors[rel] = str(e)

    if errors:
        raise DownloadError(f"Failed downloads: {errors}")

    return results


def download_and_extract_zip(
    zip_url: str,
    dest_dir: Path,
    progress: Optional[Callable[[int, int], None]] = None,
    **download_kwargs,
) -> Path:
    """Download a ZIP file and extract it. Returns the extracted root directory."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    zip_path = dest_dir / "download.zip"

    download_file(zip_url, zip_path, progress=progress, **download_kwargs)

    with zipfile.ZipFile(zip_path) as z:
        z.extractall(dest_dir / "unzip")

    zip_path.unlink()

    # Find the root directory (should contain index.html)
    roots = [p for p in (dest_dir / "unzip").iterdir() if p.is_dir() and (p / "index.html").is_file()]
    if len(roots) != 1:
        shutil.rmtree(dest_dir / "unzip", ignore_errors=True)
        raise DownloadError("Unexpected archive layout: no single index.html root")

    return roots[0]


def verify_sha256(file_path: Path, expected: str) -> bool:
    """Verify file SHA-256 hash."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower() == expected.lower()