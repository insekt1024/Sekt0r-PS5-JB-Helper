# SEKT0R AUTO JAILBREAK TOOLKIT

A self-contained, cross-platform tool to host the **Relapse exploit** (firmware 7.00–13.60) on your PC, so you can jailbreak your PS5 by simply connecting a LAN cable and entering a DNS address on the console.

> ⚠️ **Security Research Only** — For consoles you own. No piracy content included. Use at your own risk (ban/brick possible). Firmware 14.00+ cannot be jailbroken and PS5 cannot be downgraded. Turn OFF automatic updates.

---

## Features

- **One-click download** — Fetches pinned exploit host (WAK1360-Relapse), self-host overlay, and FTP payload from GitHub
- **Integrity verified** — SHA-256 checks, manifest tracking, automatic retry with exponential backoff
- **Local DNS + HTTP/HTTPS** — Redirects Sony's User Guide domains to your PC; blocks update domains
- **Self-signed TLS cert** — Auto-generates certificate for `manuals.playstation.net` (PS5 accepts the warning)
- **Cross-platform GUI** — Dark-themed tkinter UI (Windows/Linux/macOS), bilingual EN/FA
- **Admin helpers** — Set static IP, restore DHCP, add firewall rules (Windows UAC)
- **Self-test** — End-to-end verification of DNS, HTTP, HTTPS before you connect the PS5
- **Config-driven** — All parameters in `config.json` (ports, IPs, upstream sources, payloads)
- **PyInstaller ready** — Build a single `.exe` with no Python installation required
- **Modular architecture** — Clean separation of concerns for maintainability (v1.2.0)
- **DNS caching** — Response caching for improved performance (v1.2.0)
- **Parallel downloads** — Optional payloads can be downloaded in parallel (v1.2.0)
- **JSON schema validation** — Config validation with detailed error messages (v1.2.0)
- **Reduced cert validity** — 1-year cert lifetime for better security (v1.2.0)

---

## Quick Start

### Windows (Recommended)
```cmd
run.bat
```

### Python (Any OS)
```bash
python ps5_jb_helper_main.py
```

### Build Standalone EXE
```bash
pip install pyinstaller
pyinstaller ps5_jb_helper.spec
# Output: dist/Sekt0r Auto Jailbreak Tool.exe
```

---

## Usage

1. **Connect** LAN cable between PC and PS5 (or both into same router)
2. **Launch** the app → select your network adapter
3. **Click "1 · Download / Update files"** — waits for green "ready" status
4. **Click "2 · Start server"** — DNS (53), HTTP (80), HTTPS (443) start
5. **On PS5:**
   - Settings → Network → Set Up Internet Connection → Wired LAN → Advanced Settings
   - **Direct cable:** Click "Set static IP (admin)" in app, then on PS5 set:
     - IP: `192.168.100.2`
     - Subnet: `255.255.255.0`
     - Gateway: `192.168.100.1`
   - **Same router:** Leave IP settings on Automatic
   - DNS Settings → Manual → Primary DNS: **the IP shown in app** · Secondary: `0.0.0.0`
6. **Open** Settings → Guide & Tips → User's Guide → **Accept certificate warning**
7. **WAK1360 page loads** → Press **START** (may need a few reloads — WebKit is finicky)
8. **After success** → Open **PAYLOADS** → Load OnionHEN / kstuff / FTP Server

---

## Supported Firmware

| Range | Exploit | Status |
|-------|---------|--------|
| 7.00 – 13.60 | Relapse (WebKit + Kernel) | ✅ Supported |
| 14.00+ | — | ❌ Impossible (no downgrade) |

Full list in `config.json` → `firmware.supported` (60+ versions).

---

## Payloads Included

| Payload | Purpose |
|---------|
| **OnionHEN.elf** | Homebrew enabler (HEN) |
| **kstuff.elf** | Kernel tools / debugging |
| **shadowmountplus.elf** | Filesystem mount utilities |
| **ftpsrv-ps5.elf** | FTP server for file transfer |
| elfldr-ps5-1360.elf | ELF loader (optional) |
| kexp_2026_05_25.bin | Kernel exploit binary (optional) |
| nanodns.elf | DNS payload (optional) |
| webfile-manager.elf | Web file manager (owendswang/ps5-web-file-manager) for PS5 LAN file access |

Optional payloads are managed by the **payload manager** and downloadable
via the UI (Download optional). Their source URL and SHA-256 are registered
in `config/__init__.py` under `payloads.registry` (SHA-256 is validated at
download unless left `null`).

---

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 53 | UDP | DNS (redirects Sony guide domains) |
| 80 | TCP | HTTP (fallback) |
| 443 | TLS | HTTPS (User Guide + exploit page) |

**Port 53 conflict?** Windows ICS (Internet Connection Sharing) often holds UDP 53. Disable ICS or use direct-cable + static IP mode.

---

## Configuration

Edit `config.json` to customize:
- Upstream repos/refs (exploit host, overlay, ftpsrv)
- Network ports, static IP, DNS upstreams
- Required/optional payloads
- GUI theme, colors, window size
- Logging level, format

---

## Project Structure

```
ps5-jb-helper/
├── ps5_jb_helper_main.py   # Main application entry point
├── ps5_jb_helper/          # Modular package
│   ├── __init__.py         # Package exports and constants
│   ├── config/             # Configuration loading & validation
│   ├── dns/                # DNS server with domain filtering
│   ├── http/               # HTTP/HTTPS servers for exploit hosting
│   ├── download/           # Robust downloader with retry & verification
│   ├── cert/               # TLS certificate management
│   ├── network/            # Network interface & admin helpers
│   ├── utils/              # Logging, verification, utilities
│   ├── orchestrator/       # Download orchestration
│   ├── selftest/           # End-to-end self-test
│   └── i18n/               # Internationalization (EN/FA)
├── config.json             # All tunable parameters
├── test_app.py             # Unit + live integration tests
├── run.bat                 # Windows launcher
├── ps5_jb_helper.spec      # PyInstaller build spec
├── assets/
│   ├── manuals.crt         # TLS cert (auto-generated if missing)
│   └── manuals.key         # TLS key (auto-generated if missing)
└── www/                    # Downloaded at runtime (git-ignored)
    ├── index.html          # Exploit page (WAK1360 + overlay)
    ├── src/                # JS modules (firmware, helper, force-ready)
    ├── assets/             # CSS, fonts
    ├── payloads/           # .elf/.bin payloads + payloads.json
    └── offsets/            # Firmware-specific offsets (7.00–13.60)
```

---

## Requirements

- Python 3.9+ (tkinter &amp; `cryptography` included by default)
  - **Required by default:** `cryptography` for auto TLS cert generation.
    ```bash
    pip install -r requirements.txt
    ```
  - Without it, provide `assets/manuals.crt` + `manuals.key` manually.
- `PySide6>=6.7` — default GUI toolkit (tkinter fallback still runs
  `ps5_jb_helper_main.py` if PySide6 is missing).
- `pooch` — payload/host-page downloads with checksums and retry.

---

## Building from Source

```bash
git clone <this-repo>
cd ps5-jb-helper
python test_app.py          # Run unit tests
python test_app.py --live   # Run live integration tests
pyinstaller ps5_jb_helper.spec  # Build dist/PS5 Jailbreak Helper.exe
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| "Port 53 bind failed" | Disable Windows ICS, or run as Admin + click Firewall rules |
| "DNS not resolving on PS5" | Verify PC IP in app matches PS5 Primary DNS; disable IPv6 on PS5 |
| "Certificate warning on PS5" | Normal — accept it (self-signed for `manuals.playstation.net`) |
| "Exploit page stalls" | Reload User's Guide a few times; WebKit race condition is normal |
| "Download fails" | Check internet; GitHub rate limits; retry (auto-retries 3x) |
| "No adapters found" | Ensure PC has IPv4 address; try Refresh button |

---

## License

MIT (this code). Upstream content retains original licenses:
- **WAK1360-Relapse** — GPL-3.0
- **ps5-relapse-selfhost** — MIT
- **ftpsrv** — Upstream license

---

## Credits

- **Relapse Exploit** — arg0WAK, TheOfficialFloW, et al.
- **Self-host overlay** — ThatRetiredDude
- **ftpsrv** — ps5-payload-dev
- **PS5 Jailbreak research** — The entire PS5 scene

---

## Disclaimer

**For educational/security research purposes only.** Only use on consoles you own. Jailbreaking may violate Sony's ToS, risk permanent ban from PSN, and potentially brick your device. The authors accept no liability.