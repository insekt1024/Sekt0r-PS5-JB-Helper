"""Main package init for PS5 Jailbreak Helper."""
# Re-export key modules for backward compatibility
from ps5_jb_helper.config import load_config, DEFAULT_CONFIG, validate_config, save_config, CFG
from ps5_jb_helper.dns import DNSServer, DNSHandler, build_query_packet
from ps5_jb_helper.http import WebServer, ExploitHandler, map_path, create_servers
from ps5_jb_helper.download import download_file, DownloadError
from ps5_jb_helper.cert import ensure_cert, generate_self_signed_cert, verify_cert, get_cert_paths
from ps5_jb_helper.network import list_interfaces, pick_default_interface, port_owner, run_elevated, set_static_ip, set_dhcp, add_firewall_rules
from ps5_jb_helper.utils import setup_logging, verify_www, compute_required_files, create_manifest, QueueHandler
from ps5_jb_helper.orchestrator import download_all
from ps5_jb_helper.selftest import self_test, run_self_test
from ps5_jb_helper.i18n import I18n, create_i18n

# Constants (computed from config)
from pathlib import Path
import sys

def _get_base() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent

BASE = _get_base()
WWW = BASE / "www"
ASSETS = BASE / "assets"
MANIFEST = BASE / "manifest.json"
LOG_FILE = BASE / "ps5_jb_helper.log"

HOST_REPO = CFG["upstream"]["host_repo"]
HOST_REF = CFG["upstream"]["host_ref"]
FTPSRV_SHA256 = CFG["upstream"]["ftpsrv_sha256"]

REQUIRED_FILES = compute_required_files(CFG)


__all__ = [
    "load_config", "DEFAULT_CONFIG", "validate_config", "save_config", "CFG",
    "DNSServer", "DNSHandler", "build_query_packet",
    "WebServer", "ExploitHandler", "map_path", "create_servers",
    "download_file", "DownloadError",
    "ensure_cert", "generate_self_signed_cert", "verify_cert", "get_cert_paths",
    "list_interfaces", "pick_default_interface", "port_owner", "run_elevated", "set_static_ip", "set_dhcp", "add_firewall_rules",
    "setup_logging", "verify_www", "compute_required_files", "create_manifest", "QueueHandler",
    "download_all",
    "self_test", "run_self_test",
    "I18n", "create_i18n",
    "BASE", "WWW", "ASSETS", "MANIFEST", "LOG_FILE",
    "HOST_REPO", "HOST_REF", "FTPSRV_SHA256",
    "REQUIRED_FILES",
]

__version__ = "1.2.0"