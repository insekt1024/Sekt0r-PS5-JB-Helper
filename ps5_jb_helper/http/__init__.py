"""HTTP/HTTPS server module for PS5 Jailbreak Helper."""
import io
import mimetypes
import re
import ssl
import threading
import time
import urllib.parse
from collections import defaultdict
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional, Tuple, Dict


# MIME type mapping
MIME_TYPES = {
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".css": "text/css",
    ".html": "text/html; charset=utf-8",
    ".json": "application/json",
    ".elf": "application/octet-stream",
    ".bin": "application/octet-stream",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
}


class RateLimiter:
    """Token bucket rate limiter per client IP."""

    def __init__(self, rate: int = 50, burst: int = 100, window: float = 1.0):
        """
        Args:
            rate: Requests per window allowed
            burst: Maximum burst allowance
            window: Time window in seconds
        """
        self.rate = rate
        self.burst = burst
        self.window = window
        self._buckets: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_update)
        self._lock = threading.RLock()

    def _refill(self, ip: str) -> float:
        now = time.time()
        tokens, last = self._buckets.get(ip, (float(self.burst), now))
        elapsed = now - last
        tokens = min(self.burst, tokens + elapsed * self.rate / self.window)
        self._buckets[ip] = (tokens, now)
        return tokens

    def allow(self, ip: str) -> bool:
        """Check if request from IP is allowed. Returns True if allowed."""
        with self._lock:
            tokens = self._refill(ip)
            if tokens >= 1:
                self._buckets[ip] = (tokens - 1, time.time())
                return True
            return False

    def cleanup_old(self, max_age: float = 300.0) -> None:
        """Remove entries older than max_age seconds."""
        with self._lock:
            now = time.time()
            to_remove = [ip for ip, (_, last) in self._buckets.items() if now - last > max_age]
            for ip in to_remove:
                del self._buckets[ip]


# Pattern for deep asset paths like /document/en/ps5/src/firmware.js
DEEP_ASSET_RE = re.compile(r"^/document/.+/(src|assets)/(.*)$", re.IGNORECASE)


def map_path(url_path: str, www_root: Path) -> Tuple[Optional[Path], str]:
    """
    Map URL path to filesystem path (nginx-equivalent).
    Returns (file_path, mode) where mode is 'file', 'spa', or '404'.
    Never escapes www_root.
    """
    # Parse and decode URL path
    path = urllib.parse.unquote(urllib.parse.urlsplit(url_path).path)

    # Handle deep asset paths: /document/en/ps5/src/firmware.js -> /src/firmware.js
    m = DEEP_ASSET_RE.match(path)
    if m:
        path = "/" + m.group(1) + "/" + m.group(2)

    rel = path.lstrip("/")

    try:
        full = (www_root / rel).resolve()
        root = www_root.resolve()
        full.relative_to(root)  # Raises ValueError if outside root
    except (ValueError, OSError):
        return None, "404"

    ext = full.suffix.lower()

    # CRITICAL: Never SPA-fallback assets — HTML-as-JS kills the exploit silently
    if ext in (".js", ".css"):
        return (full, "file") if full.is_file() else (None, "404")

    if full.is_file():
        return full, "file"

    if full.is_dir() and (full / "index.html").is_file():
        return full / "index.html", "file"

    # SPA fallback for routes
    return www_root / "index.html", "spa"


class ExploitHandler(SimpleHTTPRequestHandler):
    """HTTP request handler for exploit hosting."""

    protocol_version = "HTTP/1.1"
    server_version = "PS5JBHelper/1.2.0"

    def send_head(self) -> Optional[io.BytesIO]:
        # Check rate limit
        client_ip = self.client_address[0]
        if not self.server._rate_limiter.allow(client_ip):
            self.send_error(429, "Too Many Requests")
            return None

        full, mode = map_path(self.path, self.server.www_root)

        if mode == "404" or full is None:
            self.send_error(404, "Not Found")
            return None

        # Determine content type
        ctype = MIME_TYPES.get(full.suffix.lower())
        if not ctype:
            ctype = mimetypes.guess_type(full.name)[0] or "application/octet-stream"

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

    def log_message(self, format: str, *args) -> None:
        """Log via server's log function."""
        if hasattr(self.server, "log_func") and self.server.log_func:
            self.server.log_func("http: " + (format % args), level="debug")


class WebServer(ThreadingHTTPServer):
    """Threaded HTTP/HTTPS server."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        ip: str,
        port: int,
        www_root: Path,
        log_func: Callable[[str, str], None],
        use_tls: bool = False,
        cert_path: Optional[Path] = None,
        key_path: Optional[Path] = None,
        rate_limit: int = 50,  # requests per second per IP
    ):
        self.www_root = Path(www_root)
        self.log_func = log_func
        self._rate_limiter = RateLimiter(rate=rate_limit, burst=rate_limit * 2)
        super().__init__((ip, port), ExploitHandler)

        if use_tls:
            if not cert_path or not key_path:
                raise ValueError("cert_path and key_path required for TLS")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            self.socket = ctx.wrap_socket(self.socket, server_side=True)

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        """Override to allow graceful shutdown."""
        super().serve_forever(poll_interval)

    def shutdown(self) -> None:
        """Graceful shutdown."""
        super().shutdown()
        self.server_close()


def create_servers(
    ip: str,
    http_port: int,
    https_port: int,
    www_root: Path,
    log_func: Callable[[str, str], None],
    cert_path: Path,
    key_path: Path,
    http_rate_limit: int = 50,
    https_rate_limit: int = 50,
) -> Tuple[WebServer, WebServer]:
    """Create HTTP and HTTPS server pair."""
    http_server = WebServer(ip, http_port, www_root, log_func, use_tls=False, rate_limit=http_rate_limit)
    https_server = WebServer(ip, https_port, www_root, log_func, use_tls=True, cert_path=cert_path, key_path=key_path, rate_limit=https_rate_limit)
    return http_server, https_server