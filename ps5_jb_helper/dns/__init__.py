"""DNS server module for PS5 Jailbreak Helper."""
import socket
import struct
import socketserver
import threading
import time
from collections import defaultdict
from typing import Optional, Tuple, Dict


# DNS constants
DNS_PORT = 53
DNS_HEADER_SIZE = 12
FLAGS_QR = 0x8000
FLAGS_AA = 0x0400
FLAGS_RA = 0x0080
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
QTYPE_A = 1
QTYPE_AAAA = 28
CLASS_IN = 1


class DNSCache:
    """Simple TTL-based DNS cache."""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self._cache: Dict[str, Tuple[bytes, float]] = {}
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._lock = threading.RLock()

    def _make_key(self, qname: str, qtype: int) -> str:
        return f"{qname}:{qtype}"

    def get(self, qname: str, qtype: int) -> Optional[bytes]:
        with self._lock:
            key = self._make_key(qname, qtype)
            if key in self._cache:
                data, expiry = self._cache[key]
                if time.time() < expiry:
                    return data
                else:
                    del self._cache[key]
        return None

    def set(self, qname: str, qtype: int, data: bytes, ttl: Optional[int] = None) -> None:
        with self._lock:
            if len(self._cache) >= self._max_size:
                # Remove oldest entry
                oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][1])
                del self._cache[oldest_key]
            key = self._make_key(qname, qtype)
            expiry = time.time() + (ttl or self._default_ttl)
            self._cache[key] = (data, expiry)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


class RateLimiter:
    """Token bucket rate limiter per client IP."""

    def __init__(self, rate: int = 100, burst: int = 200, window: float = 1.0):
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


def parse_qname(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse a DNS QNAME from packet data. Returns (name, next_offset)."""
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("Truncated name")
        ln = data[offset]
        if ln == 0:
            return ".".join(labels), offset + 1
        if ln & 0xC0:  # Compressed name - not supported in questions
            raise ValueError("Compressed question name")
        offset += 1
        labels.append(data[offset:offset + ln].decode("ascii", "replace").lower())
        offset += ln


def build_response(tid: bytes, question: bytes, qname: str, qtype: int, ip: str, ttl: int = 60) -> bytes:
    """Build a DNS A record response."""
    header = tid + struct.pack(">HHHHH", FLAGS_QR | FLAGS_AA | FLAGS_RA, 1, 1, 0, 0)
    answer = (
        b"\xc0\x0c"  # Name pointer to question
        + struct.pack(">HHIH", QTYPE_A, CLASS_IN, ttl, 4)
        + socket.inet_aton(ip)
    )
    return header + question + answer


def build_nodata_response(tid: bytes, question: bytes, ttl: int = 60) -> bytes:
    """Build a NODATA (empty answer) response."""
    header = tid + struct.pack(">HHHHH", FLAGS_QR | FLAGS_AA | FLAGS_RA, 1, 0, 0, 0)
    return header + question


def build_nxdomain_response(tid: bytes, question: bytes) -> bytes:
    """Build NXDOMAIN response."""
    header = tid + struct.pack(">HHHHH", FLAGS_QR | FLAGS_AA | 0x0003, 1, 0, 0, 0)  # RCODE=3
    return header + question


def build_query_packet(name: str, qtype: int = QTYPE_A) -> bytes:
    """Build a DNS query packet."""
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, CLASS_IN)


class DNSHandler(socketserver.BaseRequestHandler):
    """UDP DNS request handler."""

    def handle(self) -> None:
        data, sock = self.request
        client_ip = self.client_address[0]
        
        # Check rate limit
        if not self.server._rate_limiter.allow(client_ip):
            # Silently drop - don't respond to rate-limited clients
            return
        
        try:
            resp = self.server.respond(data)
        except Exception:
            resp = None
        if resp:
            try:
                sock.sendto(resp, self.client_address)
            except OSError:
                pass


class DNSServer(socketserver.ThreadingUDPServer):
    """Threaded UDP DNS server with domain filtering."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        target_ip: str,
        port: int = DNS_PORT,
        guide_domains: tuple = (),
        block_domains: tuple = (),
        upstream_dns: tuple = (),
        enable_cache: bool = True,
        rate_limit: int = 100,  # requests per second per IP
    ):
        self.target_ip = target_ip
        self.guide_domains = tuple(d.lower() for d in guide_domains)
        self.block_domains = tuple(d.lower() for d in block_domains)
        self.upstream_dns = tuple(upstream_dns)
        self._cache = DNSCache() if enable_cache else None
        self._rate_limiter = RateLimiter(rate=rate_limit, burst=rate_limit * 2)
        self._forward_lock = threading.Lock()
        super().__init__((target_ip, port), DNSHandler)

    def _matches(self, qname: str, domains: tuple) -> bool:
        """Check if qname matches any domain in the list (exact or subdomain)."""
        qname = qname.lower()
        for dom in domains:
            if qname == dom or qname.endswith("." + dom):
                return True
        return False

    def _forward_query(self, data: bytes) -> Optional[bytes]:
        """Forward query to upstream DNS servers."""
        for server in self.upstream_dns:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2.5)
                    s.sendto(data, (server, 53))
                    resp, _ = s.recvfrom(4096)
                    return resp
            except OSError:
                continue
        return None

    def respond(self, data: bytes) -> Optional[bytes]:
        """Process a DNS query and return response."""
        if len(data) < DNS_HEADER_SIZE:
            return None

        tid = data[:2]
        flags = struct.unpack(">H", data[2:4])[0]

        # Only handle standard queries
        if flags & 0x7800:  # Not a standard query
            return self._forward_query(data)

        qdcount = struct.unpack(">H", data[4:6])[0]
        if qdcount != 1:
            return self._forward_query(data)

        try:
            qname, offset = parse_qname(data, 12)
        except ValueError:
            return self._forward_query(data)

        if offset + 4 > len(data):
            return None

        qtype = struct.unpack(">H", data[offset:offset + 2])[0]
        qclass = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        if qclass != CLASS_IN:
            return self._forward_query(data)

        question = data[12:offset + 4]

        # Check cache first
        if self._cache:
            cached = self._cache.get(qname, qtype)
            if cached:
                return cached

        # Handle guide domains -> our IP
        if self._matches(qname, self.guide_domains):
            if qtype == QTYPE_A:
                resp = build_response(tid, question, qname, qtype, self.target_ip)
            else:
                # AAAA, HTTPS, etc. -> NODATA to prevent IPv6 bypass
                resp = build_nodata_response(tid, question)

        # Handle block domains -> 0.0.0.0
        elif self._matches(qname, self.block_domains):
            if qtype == QTYPE_A:
                resp = build_response(tid, question, qname, qtype, "0.0.0.0")
            else:
                resp = build_nodata_response(tid, question)

        # Forward everything else
        else:
            resp = self._forward_query(data)

        # Cache successful responses
        if resp and self._cache:
            self._cache.set(qname, qtype, resp)

        return resp

    def clear_cache(self) -> None:
        """Clear the DNS cache."""
        if self._cache:
            self._cache.clear()