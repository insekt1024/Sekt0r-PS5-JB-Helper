#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SEKT0R AUTO JAILBREAK TOOLKIT — self-host the Relapse exploit (firmware 7.00–13.60).

Downloads the public exploit host page from GitHub, then runs a local
DNS + HTTP/HTTPS server so the PS5 User's Guide loads the exploit page
over a LAN cable. Standard library only (Python 3.9+), GUI via tkinter.

MIT License (this file). Downloaded exploit content keeps its upstream
licenses: WAK1360-Relapse GPL-3.0, Relapse-Exploit MIT, ftpsrv upstream.
For security research on a console you own. No piracy content included.
"""

import ctypes
import queue
import sys
import threading
import time
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:
    print("tkinter is missing. Install Python from https://python.org (includes tkinter).")
    sys.exit(1)

# Local imports
from ps5_jb_helper import (
    load_config, DEFAULT_CONFIG,
    DNSServer, WebServer,
    ensure_cert, get_cert_paths,
    list_interfaces, pick_default_interface, port_owner, run_elevated,
    setup_logging, verify_www, compute_required_files, QueueHandler,
    download_all, run_self_test,
    I18n, create_i18n,
)

# ─── Constants ────────────────────────────────────────────────────────────

APP_NAME = "SEKT0R AUTO JAILBREAK TOOLKIT"
APP_VER = "1.2.0"


def _get_base() -> Path:
    """Get base directory for config/assets — works in both dev and frozen (PyInstaller) modes."""
    if getattr(sys, "frozen", False):
        # PyInstaller one-file: data files extracted to sys._MEIPASS
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent


BASE = _get_base()
CONFIG_FILE = BASE / "config.json"
WWW = BASE / "www"
ASSETS = BASE / "assets"
MANIFEST = BASE / "manifest.json"
LOG_FILE = BASE / "ps5_jb_helper.log"
I18N_DIR = BASE / "ps5_jb_helper" / "i18n"

# Load configuration
CFG = load_config(CONFIG_FILE)

# Extracted config values for convenience
HOST_REPO = CFG["upstream"]["host_repo"]
HOST_REF = CFG["upstream"]["host_ref"]
HOST_ZIP = f"https://codeload.github.com/{HOST_REPO}/zip/{HOST_REF}"
OVERLAY_RAW = f"https://raw.githubusercontent.com/{CFG['upstream']['overlay_repo']}/{CFG['upstream']['overlay_branch']}/overlay/"
OVERLAY_FILES = ["index.html", "src/firmware.js", "src/helper.js", "src/force-ready.js"]
OVERLAY_PAYLOADS_JSON = "payloads.json"
FTPSRV_URL = CFG["upstream"]["ftpsrv_url"]
FTPSRV_SHA256 = CFG["upstream"]["ftpsrv_sha256"]

GUIDE_DOMAINS = tuple(CFG["network"]["guide_domains"])
BLOCK_DOMAINS = tuple(CFG["network"]["block_domains"])
UPSTREAM_DNS = tuple(CFG["network"]["upstream_dns"])

DNS_PORT = CFG["network"]["dns_port"]
HTTP_PORT = CFG["network"]["http_port"]
HTTPS_PORT = CFG["network"]["https_port"]
STATIC_IP = CFG["network"]["static_ip"]
STATIC_MASK = CFG["network"]["static_mask"]
PS5_IP = CFG["network"]["ps5_ip"]

REQUIRED_FILES = compute_required_files(CFG)


# ─── GUI Application ──────────────────────────────────────────────────────


class App:
    def __init__(self, root):
        self.tk, self.ttk = tk, ttk
        self.root = root
        self.lang = "en"
        self.q = queue.Queue()
        self.servers = []
        self.busy = False
        self.interfaces = []
        self.i18n = create_i18n(I18N_DIR, "en")
        self.logger = setup_logging(self.q, CFG, LOG_FILE)
        self._build_style()
        self._build()
        self.refresh_interfaces()
        self.refresh_files_status()
        self.logger.info(f"{APP_NAME} v{APP_VER} — {self.t('exit_hint')}")
        self.root.after(100, self._drain)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # -- i18n / style
    def t(self, key: str, **kw) -> str:
        s = self.i18n.t(key)
        return s.format(**kw) if kw else s

    def _build_style(self) -> None:
        ttk = self.ttk
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        c = CFG["gui"]["colors"]
        self.BG, self.CARD, self.FG, self.ACC = c["bg"], c["card"], c["fg"], c["accent"]
        self.root.configure(bg=self.BG)
        self.style.configure(".", background=self.BG, foreground=self.FG, fieldbackground=self.CARD,
                             bordercolor=self.CARD, lightcolor=self.CARD, darkcolor=self.CARD)
        self.style.configure("TFrame", background=self.BG)
        self.style.configure("Card.TFrame", background=self.CARD)
        self.style.configure("TLabel", background=self.BG, foreground=self.FG, font=("Segoe UI", 10))
        self.style.configure("Card.TLabel", background=self.CARD, foreground=self.FG)
        self.style.configure("Big.TLabel", background=self.CARD, foreground="#7dd3fc", font=("Segoe UI", 24, "bold"))
        self.style.configure("Warn.TLabel", background="#2a2010", foreground=c["warning"], font=("Segoe UI", 9))
        self.style.configure("Dim.TLabel", background=self.BG, foreground=c["muted"], font=("Segoe UI", 9))
        self.style.configure("Success.TLabel", background=self.BG, foreground=c["success"], font=("Segoe UI", 9))
        self.style.configure("Error.TLabel", background=self.BG, foreground=c["error"], font=("Segoe UI", 9))
        self.style.configure("TButton", background=self.CARD, foreground=self.FG, font=("Segoe UI", 10), padding=6)
        self.style.map("TButton", background=[("active", "#263140"), ("disabled", "#151a20")],
                       foreground=[("disabled", "#6b7280")])
        self.style.configure("Accent.TButton", background=self.ACC, foreground="#ffffff", font=("Segoe UI", 10, "bold"))
        self.style.map("Accent.TButton", background=[("active", "#2563eb"), ("disabled", "#1e3a5f")])
        self.style.configure("TCombobox", fieldbackground=self.CARD, background=self.CARD, foreground=self.FG)
        self.style.configure("Horizontal.TProgressbar", background=self.ACC, troughcolor=self.CARD, bordercolor=self.CARD)
        self.style.configure("TLabelframe", background=self.BG, foreground=self.FG)
        self.style.configure("TLabelframe.Label", background=self.BG, foreground=c["muted"], font=("Segoe UI", 9, "bold"))

    # -- widgets
    def _build(self) -> None:
        tk, ttk = self.tk, self.ttk
        self.root.title(self.t("title"))
        
        # Restore window geometry if enabled
        if CFG["gui"].get("remember_window", True):
            try:
                geo = CFG["gui"].get("window_geometry", "")
                if geo:
                    self.root.geometry(geo)
                else:
                    self.root.geometry(CFG["gui"]["window_size"])
            except Exception:
                self.root.geometry(CFG["gui"]["window_size"])
        else:
            self.root.geometry(CFG["gui"]["window_size"])
            
        self.root.minsize(*map(int, CFG["gui"]["min_window_size"].split("x")))
        pad = {"padx": 14, "pady": 4}

        head = ttk.Frame(self.root)
        head.pack(fill="x", **pad)
        self.lbl_title = ttk.Label(head, text=self.t("title"), font=("Segoe UI", 16, "bold"))
        self.lbl_title.pack(side="left")
        self.btn_theme = ttk.Button(head, text=self.t("theme"), width=10, command=self.toggle_theme)
        self.btn_theme.pack(side="right", padx=(0, 8))
        self.btn_lang = ttk.Button(head, text=self.t("lang"), width=10, command=self.toggle_lang)
        self.btn_lang.pack(side="right")
        self.lbl_sub = ttk.Label(head, text=self.t("subtitle", version=APP_VER), style="Dim.TLabel")
        self.lbl_sub.pack(side="left", padx=10)

        self.lbl_warn = tk.Label(self.root, text=self.t("fw_warn"), bg="#2a2010", fg=CFG["gui"]["colors"]["warning"],
                                 font=("Segoe UI", 9), wraplength=820, justify="left", anchor="w", padx=10, pady=6)
        self.lbl_warn.pack(fill="x", padx=14, pady=(2, 6))

        # Firmware info
        fw_info = ttk.Label(self.root, text=self.t("firmware_info"), style="Dim.TLabel", wraplength=820)
        fw_info.pack(fill="x", padx=14, pady=(0, 6))

        row = ttk.Frame(self.root)
        row.pack(fill="x", **pad)
        self.lbl_adapter = ttk.Label(row, text=self.t("adapter"))
        self.lbl_adapter.pack(side="left")
        self.cmb_if = ttk.Combobox(row, state="readonly", width=42)
        self.cmb_if.pack(side="left", padx=8)
        self.cmb_if.bind("<<ComboboxSelected>>", lambda e: self.update_dns_label())
        self.btn_refresh = ttk.Button(row, text=self.t("refresh"), command=self.refresh_interfaces)
        self.btn_refresh.pack(side="left")

        card = ttk.Frame(self.root, style="Card.TFrame")
        card.pack(fill="x", padx=14, pady=6)
        self.lbl_dns_caption = ttk.Label(card, text=self.t("dns_label"), style="Card.TLabel")
        self.lbl_dns_caption.pack(anchor="w", padx=12, pady=(8, 0))
        inner = ttk.Frame(card, style="Card.TFrame")
        inner.pack(fill="x", padx=12, pady=(0, 10))
        self.lbl_ip = ttk.Label(inner, text="—", style="Big.TLabel")
        self.lbl_ip.pack(side="left")
        self.btn_copy = ttk.Button(inner, text=self.t("copy"), command=self.copy_ip)
        self.btn_copy.pack(side="right")

        btns = ttk.Frame(self.root)
        btns.pack(fill="x", **pad)
        self.btn_dl = ttk.Button(btns, text=self.t("download"), style="Accent.TButton", command=self.on_download)
        self.btn_dl.pack(side="left")
        self.btn_start = ttk.Button(btns, text=self.t("start"), style="Accent.TButton", command=self.on_start)
        self.btn_start.pack(side="left", padx=8)
        self.btn_stop = ttk.Button(btns, text=self.t("stop"), command=self.on_stop, state="disabled")
        self.btn_stop.pack(side="left")
        self.btn_test = ttk.Button(btns, text=self.t("verify"), command=self.on_selftest)
        self.btn_test.pack(side="left", padx=8)

        helpers = ttk.Frame(self.root)
        helpers.pack(fill="x", **pad)
        self.btn_static = ttk.Button(helpers, text=self.t("static_ip"), command=self.on_static_ip)
        self.btn_static.pack(side="left")
        self.btn_dhcp = ttk.Button(helpers, text=self.t("dhcp"), command=self.on_dhcp)
        self.btn_dhcp.pack(side="left", padx=8)
        self.btn_fw = ttk.Button(helpers, text=self.t("firewall"), command=self.on_firewall)
        self.btn_fw.pack(side="left")

        stat = ttk.Frame(self.root)
        stat.pack(fill="x", **pad)
        self.lbl_files = ttk.Label(stat, text="")
        self.lbl_files.pack(side="left")
        self.lbl_dns_stat = ttk.Label(stat, text="")
        self.lbl_dns_stat.pack(side="left", padx=16)
        self.lbl_web_stat = ttk.Label(stat, text="")
        self.lbl_web_stat.pack(side="left")
        self.progress = ttk.Progressbar(stat, mode="determinate", length=180)
        self.progress.pack(side="right")

        steps = ttk.Labelframe(self.root, text=self.t("steps_title"))
        steps.pack(fill="x", padx=14, pady=6)
        self.lbl_steps = tk.Label(steps, text=self.t("steps", ps5_ip=PS5_IP, static_mask=STATIC_MASK, static_ip=STATIC_IP),
                                  bg=self.BG, fg=self.FG, font=("Segoe UI", 9), justify="left", anchor="w", wraplength=820)
        self.lbl_steps.pack(fill="x", padx=8, pady=4)
        self.steps_frame = steps

        logf = ttk.Labelframe(self.root, text=self.t("log"))
        logf.pack(fill="both", expand=True, padx=14, pady=6)
        self.txt_log = tk.Text(logf, height=8, bg="#0b0f13", fg="#d1d5db", insertbackground="#d1d5db",
                               font=("Consolas", 9), wrap="word", state="disabled", relief="flat")
        sb = ttk.Scrollbar(logf, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt_log.pack(fill="both", expand=True, padx=4, pady=4)
        self.logf = logf

        self.lbl_disc = ttk.Label(self.root, text=self.t("disclaimer"), style="Dim.TLabel", wraplength=820)
        self.lbl_disc.pack(fill="x", padx=14, pady=(0, 8))

    def toggle_lang(self) -> None:
        new_lang = self.i18n.toggle_lang()
        self.lang = new_lang
        fa = new_lang == "fa"
        just = "right" if fa else "left"
        self.root.title(self.t("title"))
        self.lbl_title.configure(text=self.t("title"))
        self.lbl_sub.configure(text=self.t("subtitle", version=APP_VER))
        self.btn_lang.configure(text=self.t("lang"))
        self.lbl_warn.configure(text=self.t("fw_warn"), justify=just, anchor="e" if fa else "w")
        self.lbl_adapter.configure(text=self.t("adapter"))
        self.btn_refresh.configure(text=self.t("refresh"))
        self.lbl_dns_caption.configure(text=self.t("dns_label"), anchor="e" if fa else "w")
        self.btn_copy.configure(text=self.t("copy"))
        self.btn_dl.configure(text=self.t("download"))
        self.btn_start.configure(text=self.t("start"))
        self.btn_stop.configure(text=self.t("stop"))
        self.btn_test.configure(text=self.t("verify"))
        self.btn_static.configure(text=self.t("static_ip"))
        self.btn_dhcp.configure(text=self.t("dhcp"))
        self.btn_fw.configure(text=self.t("firewall"))
        self.steps_frame.configure(text=self.t("steps_title"))
        self.lbl_steps.configure(text=self.t("steps", ps5_ip=PS5_IP, static_mask=STATIC_MASK, static_ip=STATIC_IP),
                                 justify=just, anchor="e" if fa else "w")
        self.logf.configure(text=self.t("log"))
        self.lbl_disc.configure(text=self.t("disclaimer"))

    def toggle_theme(self) -> None:
        """Toggle between dark and light theme."""
        current = CFG["gui"].get("theme", "dark")
        new_theme = "light" if current == "dark" else "dark"
        CFG["gui"]["theme"] = new_theme

        # Update colors based on theme
        if new_theme == "light":
            CFG["gui"]["colors"] = {
                "bg": "#f3f4f6", "card": "#ffffff", "fg": "#1f2937", "accent": "#3b82f6",
                "success": "#22c55e", "warning": "#fbbf24", "error": "#ef4444", "muted": "#6b7280"
            }
        else:
            CFG["gui"]["colors"] = {
                "bg": "#101418", "card": "#1a2129", "fg": "#e5e7eb", "accent": "#3b82f6",
                "success": "#22c55e", "warning": "#fbbf24", "error": "#ef4444", "muted": "#9ca3af"
            }

        # Save config
        from ps5_jb_helper.config import save_config
        save_config(CFG, CONFIG_FILE)

        # Rebuild style
        self._build_style()

        # Update button text
        self.btn_theme.configure(text=self.t("theme"))

        # Refresh UI elements that need color updates
        self.refresh_files_status()
        self.refresh_server_status()

    # -- helpers
    def log(self, msg: str, level: str = "info") -> None:
        self.q.put(("log", f"[{time.strftime('%H:%M:%S')}] {msg}"))
        getattr(self.logger, level.lower(), self.logger.info)(msg)

    def _drain(self) -> None:
        try:
            while True:
                kind, *rest = self.q.get_nowait()
                if kind == "log":
                    self.txt_log.configure(state="normal")
                    self.txt_log.insert("end", rest[0] + "\n")
                    self.txt_log.see("end")
                    self.txt_log.configure(state="disabled")
                elif kind == "progress":
                    done, total = rest
                    if total:
                        self.progress.configure(mode="determinate", maximum=total, value=done)
                    else:
                        self.progress.configure(mode="indeterminate")
                        self.progress.start(12)
                elif kind == "progress_stop":
                    self.progress.stop()
                    self.progress.configure(mode="determinate", value=0)
                elif kind == "busy":
                    self.busy = rest[0]
                    state = "disabled" if self.busy else "normal"
                    self.btn_dl.configure(state=state)
                    self.btn_start.configure(state=state if not self.servers else "disabled")
                elif kind == "files_ok":
                    self.refresh_files_status()
                elif kind == "servers":
                    self.refresh_server_status()
                elif kind == "ifaces":
                    self.interfaces = rest[0]
                    self.cmb_if.configure(values=[f"{alias} — {ip}" for ip, alias in self.interfaces])
                    if self.interfaces:
                        cur = self.selected_ip()
                        want = cur if any(ip == cur for ip, _ in self.interfaces) else pick_default_interface(self.interfaces)
                        for i, (ip, _) in enumerate(self.interfaces):
                            if ip == want:
                                self.cmb_if.current(i)
                                break
                    self.update_dns_label()
                elif kind == "selftest_done":
                    ok = rest[0]
                    self.log(self.t("test_pass") if ok else self.t("test_fail"),
                             level="info" if ok else "error")
                    self.btn_test.configure(state="normal")
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def selected_ip(self) -> str:
        i = self.cmb_if.current()
        if 0 <= i < len(self.interfaces):
            return self.interfaces[i][0]
        return ""

    def selected_alias(self) -> str:
        i = self.cmb_if.current()
        if 0 <= i < len(self.interfaces):
            return self.interfaces[i][1]
        return ""

    def update_dns_label(self) -> None:
        self.lbl_ip.configure(text=self.selected_ip() or "—")

    def copy_ip(self) -> None:
        ip = self.selected_ip()
        if ip:
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.log(self.t("copied"))

    def refresh_interfaces(self) -> None:
        def work() -> None:
            self.q.put(("ifaces", list_interfaces()))
        threading.Thread(target=work, daemon=True).start()

    def files_ready(self) -> bool:
        return (WWW / "index.html").is_file() and not verify_www(WWW, REQUIRED_FILES)

    def refresh_files_status(self) -> None:
        ok = (WWW / "index.html").is_file()
        txt = self.t("ready") if ok else self.t("not_ready")
        extra = ""
        if MANIFEST.is_file():
            try:
                import json
                extra = " · " + json.loads(MANIFEST.read_text(encoding="utf-8")).get("downloaded_at", "")
            except Exception:
                pass
        color = CFG["gui"]["colors"]["success"] if ok else CFG["gui"]["colors"]["warning"]
        self.lbl_files.configure(text=f"● {self.t('files')}: {txt}{extra}", foreground=color)

    def refresh_server_status(self) -> None:
        running = bool(self.servers)
        dns_up = any(isinstance(s, DNSServer) for s in self.servers)
        web_up = sum(1 for s in self.servers if isinstance(s, WebServer))
        self.lbl_dns_stat.configure(
            text=f"● {self.t('dns')}: {self.t('running') if dns_up else self.t('stopped')}",
            foreground=CFG["gui"]["colors"]["success"] if dns_up else CFG["gui"]["colors"]["muted"])
        self.lbl_web_stat.configure(
            text=f"● {self.t('web')}: {self.t('running') if web_up == 2 else self.t('stopped')}",
            foreground=CFG["gui"]["colors"]["success"] if web_up == 2 else CFG["gui"]["colors"]["muted"])
        self.btn_start.configure(state="disabled" if running or self.busy else "normal")
        self.btn_stop.configure(state="normal" if running else "disabled")
        self.btn_test.configure(state="normal" if running else "disabled")

    # -- actions
    def on_download(self) -> None:
        if self.busy:
            return
        self.q.put(("busy", True))
        # Ensure cert exists before download completes
        def cert_work() -> None:
            if not ensure_cert(ASSETS):
                self.log(self.t("cert_fail"), level="warning")
        threading.Thread(target=cert_work, daemon=True).start()

        def work() -> None:
            try:
                def prog(done: int, total: int) -> None:
                    self.q.put(("progress", done, total))
                download_all(WWW, self.log, progress=prog, config=CFG)
                self.q.put(("progress_stop",))
                self.log(self.t("dl_ok"))
                self.q.put(("files_ok",))
            except Exception as e:
                self.q.put(("progress_stop",))
                self.log(self.t("dl_fail", err=e), level="error")
            finally:
                self.q.put(("busy", False))
        threading.Thread(target=work, daemon=True).start()

    def on_start(self) -> None:
        if self.busy or self.servers:
            return
        if not (WWW / "index.html").is_file():
            self.log(self.t("need_files"), level="warning")
            return
        ip = self.selected_ip()
        if not ip:
            self.log(self.t("no_adapter"), level="warning")
            return
        problems = verify_www(WWW, REQUIRED_FILES)
        if problems:
            self.log("Integrity problems: " + "; ".join(problems) + " — re-download.", level="error")
            return
        # Ensure cert
        if not ensure_cert(ASSETS):
            self.log(self.t("cert_fail"), level="error")
            return
        
        # Get rate limits from config
        dns_rate_limit = CFG["network"].get("dns_rate_limit", 100)
        http_rate_limit = CFG["network"].get("http_rate_limit", 50)
        https_rate_limit = CFG["network"].get("https_rate_limit", 50)
        
        made = []
        try:
            dns = DNSServer(ip, DNS_PORT, GUIDE_DOMAINS, BLOCK_DOMAINS, UPSTREAM_DNS, rate_limit=dns_rate_limit)
            made.append(dns)
            http = WebServer(ip, HTTP_PORT, WWW, self.log, rate_limit=http_rate_limit)
            made.append(http)
            crt_path, key_path = get_cert_paths(ASSETS)
            https = WebServer(ip, HTTPS_PORT, WWW, self.log, use_tls=True, cert_path=crt_path, key_path=key_path, rate_limit=https_rate_limit)
            made.append(https)
        except OSError as e:
            for s in made:
                s.shutdown()
                s.server_close()
            what = ("DNS", "HTTP", "HTTPS")[len(made)]
            port = (DNS_PORT, HTTP_PORT, HTTPS_PORT)[len(made)]
            self.log(self.t("bind_fail", what=what, ip=ip, port=port, err=e), level="error")
            owner = port_owner(port)
            if owner:
                self.log(f"Port {port} is held by: {owner}")
            if port == DNS_PORT:
                self.log(self.t("port_hint"))
            return
        self.servers = made
        for s in made:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        self.log(self.t("started", ip=ip))
        self.refresh_server_status()

    def on_stop(self) -> None:
        for s in self.servers:
            try:
                s.shutdown()
                s.server_close()
            except Exception:
                pass
        self.servers = []
        self.log(self.t("stopped_msg"))
        self.refresh_server_status()

    def on_selftest(self) -> None:
        if not self.servers:
            return
        ip = self.selected_ip()
        self.btn_test.configure(state="disabled")
        self.log(self.t("test_running"))

        def work() -> None:
            ok = run_self_test(ip, CFG, self.log)
            self.q.put(("selftest_done", ok))
        threading.Thread(target=work, daemon=True).start()

    def _elev(self, args: str, ok_msg: str) -> None:
        if os.name != "nt":
            self.log("Admin helpers are Windows-only.", level="warning")
            return
        if run_elevated("netsh.exe", args):
            self.log(self.t("elev_ok", what=ok_msg))
        else:
            self.log(self.t("elev_fail"), level="error")

    def on_static_ip(self) -> None:
        import os
        alias = self.selected_alias()
        if not alias or alias in ("?", "adapter"):
            self.log(self.t("no_adapter"), level="warning")
            return
        self._elev(f'interface ip set address name="{alias}" static {STATIC_IP} {STATIC_MASK}',
                   self.t("static_done", alias=alias, ip=STATIC_IP))
        self.root.after(2500, self.refresh_interfaces)

    def on_dhcp(self) -> None:
        import os
        alias = self.selected_alias()
        if not alias or alias in ("?", "adapter"):
            self.log(self.t("no_adapter"), level="warning")
            return
        self._elev(f'interface ip set address name="{alias}" dhcp',
                   self.t("dhcp_done", alias=alias))
        self.root.after(2500, self.refresh_interfaces)

    def on_firewall(self) -> None:
        import os
        if os.name != "nt":
            self.log("Admin helpers are Windows-only.", level="warning")
            return
        ok = True
        for name, proto, port in (("PS5 JB Helper DNS", "UDP", 53),
                                  ("PS5 JB Helper HTTP", "TCP", 80),
                                  ("PS5 JB Helper HTTPS", "TCP", 443)):
            ok = run_elevated("netsh.exe",
                              f'advfirewall firewall add rule name="{name}" dir=in action=allow protocol={proto} localport={port}') and ok
        self.log(self.t("fw_done") if ok else self.t("elev_fail"), level="info" if ok else "error")

    def on_close(self) -> None:
        try:
            self.on_stop()
        finally:
            # Save window geometry if enabled
            if CFG["gui"].get("remember_window", True):
                try:
                    geo = self.root.geometry()
                    CFG["gui"]["window_geometry"] = geo
                    # Save config to file
                    from ps5_jb_helper.config import save_config
                    save_config(CFG, CONFIG_FILE)
                except Exception:
                    pass
            self.root.destroy()


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()