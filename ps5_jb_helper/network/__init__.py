"""Network utilities for PS5 Jailbreak Helper."""
import json
import os
import socket
import subprocess
import sys
from typing import List, Tuple, Optional


def list_interfaces() -> List[Tuple[str, str]]:
    """
    List network interfaces with IPv4 addresses.
    Returns [(ip, alias), ...]
    """
    # Windows: PowerShell (locale-safe)
    if os.name == "nt":
        try:
            cmd = (
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
                "Get-NetIPAddress -AddressFamily IPv4 "
                "| Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } "
                "| Select-Object IPAddress,InterfaceAlias | ConvertTo-Json -Compress"
            )
            out = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", cmd],
                capture_output=True, encoding="utf-8", timeout=20
            )
            data = json.loads(out.stdout or "[]")
            if isinstance(data, dict):
                data = [data]
            res = [(d["IPAddress"], d.get("InterfaceAlias", "?")) for d in data if d.get("IPAddress")]
            if res:
                return res
        except Exception:
            pass

    # Linux: ip addr show
    try:
        out = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            data = json.loads(out.stdout)
            res = []
            for iface in data:
                if iface.get("operstate") != "UP":
                    continue
                alias = iface.get("ifname", "?")
                for addr in iface.get("addr_info", []):
                    if addr.get("family") == "inet":
                        ip = addr.get("local")
                        if ip and not ip.startswith("127."):
                            res.append((ip, alias))
            if res:
                return res
    except Exception:
        pass

    # macOS/BSD: ifconfig
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            res = []
            current_alias = None
            for line in out.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith(("\t", " ")):
                    current_alias = line.split(":")[0]
                elif "inet " in line and not line.startswith("inet6"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        if not ip.startswith("127."):
                            res.append((ip, current_alias or "?"))
            if res:
                return res
    except Exception:
        pass

    # Fallback: socket.getaddrinfo
    seen, res = set(), []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in seen and not ip.startswith("127."):
                seen.add(ip)
                res.append((ip, "adapter"))
    except OSError:
        pass

    return res


def pick_default_interface(interfaces: List[Tuple[str, str]]) -> str:
    """Pick the best default interface IP."""
    # Windows ICS / mobile hotspot
    for ip, _ in interfaces:
        if ip == "192.168.137.1":
            return ip
    # Private ranges
    for ip, _ in interfaces:
        if ip.startswith(("192.168.", "10.", "172.")):
            return ip
    return interfaces[0][0] if interfaces else ""


def port_owner(port: int) -> str:
    """Best-effort 'who holds this port' for error messages (Windows)."""
    if os.name != "nt":
        return ""

    try:
        out = subprocess.run(
            ["netstat", "-ano", "-p", "UDP"],
            capture_output=True, text=True, timeout=10
        ).stdout
        pids = set()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].upper() == "UDP" and parts[1].endswith(f":{port}"):
                pids.add(parts[-1])
        names = []
        for pid in pids:
            t = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=10
            ).stdout.strip()
            names.append(t.split(",")[0].strip('"') if t else f"PID {pid}")
        return ", ".join(sorted(set(names)))
    except Exception:
        return ""


def run_elevated(exe: str, args: str) -> bool:
    """ShellExecute 'runas' — triggers the UAC prompt. Windows only."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
        return rc > 32
    except Exception:
        return False


def set_static_ip(alias: str, ip: str, mask: str) -> bool:
    """Set static IP on Windows interface."""
    if os.name != "nt":
        return False
    return run_elevated("netsh.exe", f'interface ip set address name="{alias}" static {ip} {mask}')


def set_dhcp(alias: str) -> bool:
    """Restore DHCP on Windows interface."""
    if os.name != "nt":
        return False
    return run_elevated("netsh.exe", f'interface ip set address name="{alias}" dhcp')


def add_firewall_rules() -> bool:
    """Add firewall allow rules for DNS, HTTP, HTTPS."""
    if os.name != "nt":
        return False

    ok = True
    rules = [
        ("PS5 JB Helper DNS", "UDP", 53),
        ("PS5 JB Helper HTTP", "TCP", 80),
        ("PS5 JB Helper HTTPS", "TCP", 443),
    ]

    for name, proto, port in rules:
        ok = run_elevated(
            "netsh.exe",
            f'advfirewall firewall add rule name="{name}" dir=in action=allow protocol={proto} localport={port}'
        ) and ok

    return ok