"""PySide6 user interface for the PS5 Jailbreak Helper.

A faithful, modern port of the original tkinter ``App``. Replaces the
standard-library-only GUI with a native Qt6 window (dark/glass colour
scheme, animated widgets) while keeping the exact same controller
logic (``on_download``, ``on_start``, ``_drain``, …).

Falls back to the tkinter app if PySide6 is unavailable.
"""
from __future__ import annotations

import ctypes
import queue
import sys
import threading
import time
from pathlib import Path

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QClipboard, QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QLabel,
    QLayout,
    QHBoxLayout,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QScrollBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ps5_jb_helper import (
    load_config,
    DEFAULT_CONFIG,
    DNSServer,
    WebServer,
    ensure_cert,
    get_cert_paths,
    list_interfaces,
    pick_default_interface,
    port_owner,
    run_elevated,
    setup_logging,
    verify_www,
    compute_required_files,
    QueueHandler,
    download_all,
    run_self_test,
    I18n,
    create_i18n,
    GUIDE_DOMAINS,
    BLOCK_DOMAINS,
    UPSTREAM_DNS,
    DNS_PORT,
    HTTP_PORT,
    HTTPS_PORT,
    STATIC_IP,
    STATIC_MASK,
    PS5_IP,
)
from ps5_jb_helper.config import CFG, CONFIG_FILE, save_config

# ─── constants ─────────────────────────────────────────────────────────────

APP_NAME = "Sekt0r Auto Jailbreak Tool"
APP_VER = "1.2.0"

# Same base-dir resolution as the tkinter entry point.
def _get_base() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent.parent


BASE = _get_base()
WWW = BASE / "www"
ASSETS = BASE / "assets"
MANIFEST = BASE / "manifest.json"
LOG_FILE = BASE / "ps5_jb_helper.log"
I18N_DIR = BASE / "ps5_jb_helper" / "i18n"


# ─── QSS theme for the dark/light scheme ────────────────────────────────────

# ---- QSS theme for the dark/light scheme (built as single-line rules) ----
def _theme_sheet(theme: str) -> str:
    if theme == "light":
        c = {"bg": "#f3f4f6", "card": "#ffffff", "fg": "#1f2937", "accent": "#3b82f6",
             "success": "#22c55e", "warning": "#fbbf24", "error": "#ef4444", "muted": "#6b7280"}
    else:
        c = {"bg": "#101418", "card": "#1a2129", "fg": "#e5e7eb", "accent": "#3b82f6",
             "success": "#22c55e", "warning": "#fbbf24", "error": "#ef4444", "muted": "#9ca3af"}
    rules = [
        f"QWidget {{ background: {c['bg']}; color: {c['fg']}; font-family: Segoe UI; font-size: 10pt; }}",
        f"QFrame {{ background: {c['bg']}; }}",
        'QFrame[frameShape="NoFrame"] { border: none; }',
        "QLabel {{ background: {bg}; color: {fg}; font-family: Segoe UI; font-size: 10pt; }}".format(bg=c["bg"], fg=c["fg"]),
        f"QLabel#BigLabel {{ background: {c['card']}; color: #7dd3fc; font-weight: bold; font-size: 24pt; }}",
        f"QLabel#WarnLabel {{ background: #2a2010; color: {c['warning']}; font-size: 9pt; }}",
        f"QLabel#DimLabel {{ background: {c['bg']}; color: {c['muted']}; font-size: 9pt; }}",
        f"QLabel#SuccessLabel {{ background: {c['bg']}; color: {c['success']}; font-size: 9pt; }}",
        f"QLabel#ErrorLabel {{ background: {c['bg']}; color: {c['error']}; font-size: 9pt; }}",
        f"QPushButton {{ background: {c['card']}; color: {c['fg']}; font-family: Segoe UI; font-size: 10pt; padding: 6px 10px; border-radius: 4px; border: 1px solid {c['card']}; }}",
        "QPushButton:hover { background: #263140; }",
        "QPushButton:disabled { background: #151a20; color: #6b7280; }",
        f"QPushButton#AccentButton {{ background: {c['accent']}; color: #ffffff; font-weight: bold; border: none; }}",
        "QPushButton#AccentButton:hover { background: #2563eb; }",
        "QPushButton#AccentButton:disabled { background: #1e3a5f; }",
        f"QComboBox {{ background: {c['card']}; color: {c['fg']}; border: 1px solid {c['card']}; padding: 4px; }}",
        f"QProgressBar {{ background: {c['card']}; border: 1px solid {c['card']}; border-radius: 4px; }}",
        "QProgressBar::chunk {{ background: {accent}; border-radius: 4px; }}".format(accent=c["accent"]),
        f"QTextEdit {{ background: #0b0f13; color: #d1d5db; font-family: Consolas; font-size: 9pt; border: none; }}",
        "QTextEdit:focus { border: none; }",
        f"QLabel#StepsLabel {{ background: {c['bg']}; color: {c['fg']}; font-family: Segoe UI; font-size: 9pt; }}",
        "QLabel#FilesLabel, QLabel#DnsLabel, QLabel#WebLabel {{ background: {bg}; font-family: Segoe UI; font-size: 9pt; }}".format(bg=c["bg"]),
        f"QLabel#LogLabel {{ background: {c['bg']}; color: {c['muted']}; font-family: Segoe UI; font-size: 9pt; }}",
        f"QLabel#DisclaimerLabel {{ background: {c['bg']}; color: {c['muted']}; font-size: 9pt; }}",
    ]
    return chr(10).join(rules)


class AppWindow(QWidget):
    """Main window — port of the original tkinter ``App``."""

    def __init__(self) -> None:
        super().__init__()
        self.tk = None  # placeholder for legacy code paths
        self.root = self
        self.lang = "en"
        self.q: queue.Queue = queue.Queue()
        self.servers: list = []
        self.busy = False
        self.interfaces: list = []
        self.i18n = create_i18n(I18N_DIR, "en")
        self.logger = setup_logging(self.q, CFG, LOG_FILE)

        self.setWindowTitle(self.t("title"))
        self.setMinimumSize(*map(int, CFG["gui"]["min_window_size"].split("x")))
        self.setStyleSheet(_theme_sheet(CFG["gui"].get("theme", "dark")))

        self._build_style()
        self._build()
        self.refresh_interfaces()
        self.refresh_files_status()
        self.logger.info(f"{APP_NAME} v{APP_VER} — {self.t('exit_hint')}")

        self._drain_timer = QTimer(self)
        self._drain_timer.timeout.connect(self._drain)
        self._drain_timer.start(100)
        self.setAttribute(Qt.WA_DeleteOnClose)

    # -- i18n / style ------------------------------------------------------ #

    def t(self, key: str, **kw) -> str:
        s = self.i18n.t(key)
        return s.format(**kw) if kw else s

    def _build_style(self) -> None:
        self.setStyleSheet(_theme_sheet(CFG["gui"].get("theme", "dark")))

    # -- widgets ---------------------------------------------------------- #

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setSpacing(4)
        outer.setContentsMargins(14, 4, 14, 4)

        head = QHBoxLayout()
        self.lbl_title = QLabel(self.t("title"))
        self.lbl_title.setObjectName("BigLabel")
        head.addWidget(self.lbl_title)
        head.addStretch()
        self.lbl_sub = QLabel(self.t("subtitle", version=APP_VER))
        self.lbl_sub.setObjectName("DimLabel")
        head.addWidget(self.lbl_sub)
        self.btn_lang = QPushButton(self.t("lang"))
        self.btn_lang.setObjectName("AccentButton")
        self.btn_lang.clicked.connect(self.toggle_lang)
        head.addWidget(self.btn_lang)
        outer.addLayout(head)

        self.lbl_warn = QLabel(self.t("fw_warn"))
        self.lbl_warn.setObjectName("WarnLabel")
        self.lbl_warn.setStyleSheet(
            f"background: #2a2010; color: {CFG['gui']['colors']['warning']}; "
            f"font-size: 9pt; padding: 6px 10px;"
        )
        outer.addWidget(self.lbl_warn)

        self.lbl_fw_info = QLabel(self.t("firmware_info"))
        self.lbl_fw_info.setObjectName("DimLabel")
        outer.addWidget(self.lbl_fw_info)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.lbl_adapter = QLabel(self.t("adapter"))
        row.addWidget(self.lbl_adapter)
        self.cmb_if = QComboBox()
        self.cmb_if.currentTextChanged.connect(lambda e: self.update_dns_label())
        row.addWidget(self.cmb_if)
        self.btn_refresh = QPushButton(self.t("refresh"))
        self.btn_refresh.clicked.connect(self.refresh_interfaces)
        row.addWidget(self.btn_refresh)
        outer.addLayout(row)

        card = QFrame()
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 8, 12, 12)
        self.lbl_dns_caption = QLabel(self.t("dns_label"))
        self.lbl_dns_caption.setObjectName("DimLabel")
        card_layout.addWidget(self.lbl_dns_caption)
        inner = QHBoxLayout()
        inner.setContentsMargins(12, 0, 12, 10)
        self.lbl_ip = QLabel("—")
        self.lbl_ip.setObjectName("BigLabel")
        inner.addWidget(self.lbl_ip)
        self.btn_copy = QPushButton(self.t("copy"))
        self.btn_copy.setObjectName("AccentButton")
        self.btn_copy.clicked.connect(self.copy_ip)
        inner.addWidget(self.btn_copy)
        card_layout.addLayout(inner)
        outer.addWidget(card)

        btns = QHBoxLayout()
        btns.setSpacing(8)
        self.btn_dl = QPushButton(self.t("download"))
        self.btn_dl.setObjectName("AccentButton")
        self.btn_dl.clicked.connect(self.on_download)
        btns.addWidget(self.btn_dl)
        self.btn_start = QPushButton(self.t("start"))
        self.btn_start.setObjectName("AccentButton")
        self.btn_start.clicked.connect(self.on_start)
        btns.addWidget(self.btn_start)
        self.btn_stop = QPushButton(self.t("stop"))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.on_stop)
        btns.addWidget(self.btn_stop)
        self.btn_test = QPushButton(self.t("verify"))
        self.btn_test.clicked.connect(self.on_selftest)
        btns.addWidget(self.btn_test)
        outer.addLayout(btns)

        helpers = QHBoxLayout()
        helpers.setSpacing(8)
        self.btn_static = QPushButton(self.t("static_ip"))
        self.btn_static.clicked.connect(self.on_static_ip)
        helpers.addWidget(self.btn_static)
        self.btn_dhcp = QPushButton(self.t("dhcp"))
        self.btn_dhcp.clicked.connect(self.on_dhcp)
        helpers.addWidget(self.btn_dhcp)
        self.btn_fw = QPushButton(self.t("firewall"))
        self.btn_fw.clicked.connect(self.on_firewall)
        helpers.addWidget(self.btn_fw)
        self.btn_theme = QPushButton(self.t("theme"))
        self.btn_theme.clicked.connect(self.toggle_theme)
        helpers.addWidget(self.btn_theme)
        self.btn_dl_opt = QPushButton(self.t("dl_opt"))
        self.btn_dl_opt.clicked.connect(self.on_dl_optional)
        helpers.addWidget(self.btn_dl_opt)
        outer.addLayout(helpers)

        stat = QHBoxLayout()
        stat.setSpacing(16)
        self.lbl_files = QLabel("")
        stat.addWidget(self.lbl_files)
        self.lbl_dns_stat = QLabel("")
        stat.addWidget(self.lbl_dns_stat)
        self.lbl_web_stat = QLabel("")
        stat.addWidget(self.lbl_web_stat)
        self.progress = QProgressBar()
        self.progress.setFixedWidth(180)
        self.progress.setRange(0, 0)  # indeterminate by default
        stat.addWidget(self.progress)
        outer.addLayout(stat)

        steps = QFrame()
        steps_layout = QVBoxLayout(steps)
        self.lbl_steps = QLabel(self.t("steps", ps5_ip=PS5_IP, static_mask=STATIC_MASK, static_ip=STATIC_IP))
        self.lbl_steps.setObjectName("StepsLabel")
        steps_layout.addWidget(self.lbl_steps)
        outer.addWidget(steps)

        logf = QFrame()
        logf_layout = QVBoxLayout(logf)
        logf_layout.setContentsMargins(4, 4, 4, 4)
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        sb = QScrollBar()
        sb.setOrientation(Qt.Vertical)
        self.txt_log.setVerticalScrollBar(sb)
        logf_layout.addWidget(self.txt_log)
        outer.addWidget(logf)

        self.lbl_disc = QLabel(self.t("disclaimer"))
        self.lbl_disc.setObjectName("DisclaimerLabel")
        outer.addWidget(self.lbl_disc)

        self.setLayout(outer)

    # -- theme / lang ------------------------------------------------------ #

    def toggle_theme(self) -> None:
        current = CFG["gui"].get("theme", "dark")
        new_theme = "light" if current == "dark" else "dark"
        CFG["gui"]["theme"] = new_theme
        CFG["gui"]["colors"] = (
            {"bg": "#f3f4f6", "card": "#ffffff", "fg": "#1f2937", "accent": "#3b82f6",
             "success": "#22c55e", "warning": "#fbbf24", "error": "#ef4444", "muted": "#6b7280"}
            if new_theme == "light"
            else {"bg": "#101418", "card": "#1a2129", "fg": "#e5e7eb", "accent": "#3b82f6",
                  "success": "#22c55e", "warning": "#fbbf24", "error": "#ef4444", "muted": "#9ca3af"}
        )
        save_config(CFG, CONFIG_FILE)
        self.setStyleSheet(_theme_sheet(new_theme))
        self.btn_theme.setText(self.t("theme"))
        self.refresh_files_status()
        self.refresh_server_status()

    def toggle_lang(self) -> None:
        new_lang = self.i18n.toggle_lang()
        self.lang = new_lang
        self.setLayoutDirection(
            Qt.LayoutDirection.RightToLeft if self.i18n.is_rtl else Qt.LayoutDirection.LeftToRight
        )
        self.lbl_title.setText(self.t("title"))
        self.lbl_sub.setText(self.t("subtitle", version=APP_VER))
        self.lbl_warn.setText(self.t("fw_warn"))
        self.lbl_warn.setStyleSheet(
            f"background: #2a2010; color: {CFG['gui']['colors']['warning']}; font-size: 9pt; padding: 6px 10px;"
        )
        self.lbl_adapter.setText(self.t("adapter"))
        self.lbl_dns_caption.setText(self.t("dns_label"))
        self.btn_copy.setText(self.t("copy"))
        self.btn_dl.setText(self.t("download"))
        self.btn_start.setText(self.t("start"))
        self.btn_stop.setText(self.t("stop"))
        self.btn_test.setText(self.t("verify"))
        self.btn_static.setText(self.t("static_ip"))
        self.btn_dhcp.setText(self.t("dhcp"))
        self.btn_fw.setText(self.t("firewall"))
        self.lbl_steps.setText(self.t("steps", ps5_ip=PS5_IP, static_mask=STATIC_MASK, static_ip=STATIC_IP))
        self.lbl_disc.setText(self.t("disclaimer"))
        self.btn_lang.setText(self.t("lang"))
        self.refresh_files_status()
        self.refresh_server_status()

    # -- helpers --------------------------------------------------------- #

    def log(self, msg: str, level: str = "info") -> None:
        self.q.put(("log", f"[{time.strftime('%H:%M:%S')}] {msg}"))
        getattr(self.logger, level.lower(), self.logger.info)(msg)

    def _drain(self) -> None:
        try:
            while True:
                kind, *rest = self.q.get_nowait()
                if kind == "log":
                    self.txt_log.append(rest[0])
                elif kind == "progress":
                    done, total = rest
                    if total:
                        self.progress.setRange(0, total)
                        self.progress.setValue(done)
                    else:
                        self.progress.setRange(0, 0)
                        self.progress.setValue(0)
                elif kind == "progress_stop":
                    self.progress.setRange(0, 0)
                    self.progress.setValue(0)
                elif kind == "busy":
                    self.busy = rest[0]
                    self.btn_dl.setEnabled(not self.busy)
                    self.btn_start.setEnabled(not self.busy and not self.servers)
                elif kind == "files_ok":
                    self.refresh_files_status()
                elif kind == "servers":
                    self.refresh_server_status()
                elif kind == "ifaces":
                    self.interfaces = rest[0]
                    self.cmb_if.clear()
                    self.cmb_if.addItems([f"{alias} — {ip}" for ip, alias in self.interfaces])
                    if self.interfaces:
                        cur = self.selected_ip()
                        want = cur if any(ip == cur for ip, _ in self.interfaces) else pick_default_interface(self.interfaces)
                        for i, (ip, _alias) in enumerate(self.interfaces):
                            if ip == want:
                                self.cmb_if.setCurrentIndex(i)
                                break
                    self.update_dns_label()
                elif kind == "selftest_done":
                    ok = rest[0]
                    self.log(self.t("test_pass") if ok else self.t("test_fail"),
                             level="info" if ok else "error")
                    self.btn_test.setEnabled(True)
        except queue.Empty:
            pass
        self._drain_timer.start(100)

    # -- queries --------------------------------------------------------- #

    def selected_ip(self) -> str:
        i = self.cmb_if.currentIndex()
        if 0 <= i < len(self.interfaces):
            return self.interfaces[i][0]
        return ""

    def selected_alias(self) -> str:
        i = self.cmb_if.currentIndex()
        if 0 <= i < len(self.interfaces):
            return self.interfaces[i][1]
        return ""

    def update_dns_label(self) -> None:
        self.lbl_ip.setText(self.selected_ip() or "—")

    def copy_ip(self) -> None:
        ip = self.selected_ip()
        if ip:
            clipboard: QClipboard = QApplication.clipboard()
            clipboard.setText(ip)
            self.log(self.t("copied"))

    # -- status ---------------------------------------------------------- #

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
        self.lbl_files.setText(f"● {self.t('files')}: {txt}{extra}")
        self.lbl_files.setStyleSheet(f"color: {color};")

    def refresh_server_status(self) -> None:
        running = bool(self.servers)
        dns_up = any(isinstance(s, DNSServer) for s in self.servers)
        web_up = sum(1 for s in self.servers if isinstance(s, WebServer))
        self.lbl_dns_stat.setText(f"● {self.t('dns')}: {self.t('running') if dns_up else self.t('stopped')}")
        self.lbl_dns_stat.setStyleSheet(
            f"color: {'#22c55e' if dns_up else '#9ca3af'};")
        self.lbl_web_stat.setText(
            f"● {self.t('web')}: {self.t('running') if web_up == 2 else self.t('stopped')}")
        self.lbl_web_stat.setStyleSheet(
            f"color: {'#22c55e' if web_up == 2 else '#9ca3af'};")
        self.btn_start.setEnabled(not running and not self.busy)
        self.btn_stop.setEnabled(running)
        self.btn_test.setEnabled(running)

    # -- actions --------------------------------------------------------- #

    def on_download(self) -> None:
        if self.busy:
            return
        self.q.put(("busy", True))

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
            except Exception as e:  # noqa: BLE001
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
        if not ensure_cert(ASSETS):
            self.log(self.t("cert_fail"), level="error")
            return

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

    def on_dl_optional(self) -> None:
        if self.busy or self.servers:
            return
        self.q.put(("busy", True))

        def work() -> None:
            try:
                from ps5_jb_helper.orchestrator import download_payloads_parallel
                installed = download_payloads_parallel(
                    WWW,
                    CFG,
                    lambda msg, level="info": self.q.put(("log", f"[{time.strftime('%H:%M:%S')}] {msg}")),
                    progress=lambda kind, done, total: self.q.put(("progress", done, total)),
                )
                for name, path in installed.items():
                    self.q.put(("log", f"Installed {name} -> {path}"))
                self.q.put(("progress_stop",))
                self.log(self.t("dl_ok"))
                self.q.put(("files_ok",))
            except Exception as e:  # noqa: BLE001
                self.q.put(("progress_stop",))
                self.log(self.t("dl_fail", err=e), level="error")
            finally:
                self.q.put(("busy", False))

        threading.Thread(target=work, daemon=True).start()

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
        self.btn_test.setEnabled(False)
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
        alias = self.selected_alias()
        if not alias or alias in ("?", "adapter"):
            self.log(self.t("no_adapter"), level="warning")
            return
        self._elev(
            f'interface ip set address name="{alias}" static {STATIC_IP} {STATIC_MASK}',
            self.t("static_done", alias=alias, ip=STATIC_IP),
        )
        QTimer.singleShot(2500, self.refresh_interfaces)

    def on_dhcp(self) -> None:
        alias = self.selected_alias()
        if not alias or alias in ("?", "adapter"):
            self.log(self.t("no_adapter"), level="warning")
            return
        self._elev(
            f'interface ip set address name="{alias}" dhcp',
            self.t("dhcp_done", alias=alias),
        )
        QTimer.singleShot(2500, self.refresh_interfaces)

    def on_firewall(self) -> None:
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

    def closeEvent(self, event) -> None:
        try:
            self.on_stop()
        finally:
            if CFG["gui"].get("remember_window", True):
                try:
                    CFG["gui"]["window_geometry"] = self.saveGeometry().toString()
                    save_config(CFG, CONFIG_FILE)
                except Exception:
                    pass
            super().closeEvent(event)


# ─── entry point ----------------------------------------------------------- #

def main() -> None:
    app = QApplication(sys.argv)
    window = AppWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
