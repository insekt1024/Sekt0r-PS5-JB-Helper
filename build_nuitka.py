#!/usr/bin/env python3
"""
Nuitka build script for PS5 Jailbreak Helper (tkinter standalone).
Builds a single-file Windows executable.
"""
import subprocess
import sys
import os

def build():
    # Ensure we're in the right directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Nuitka command
    cmd = [
        sys.executable, "-m", "nuitka",
        "--onefile",
        "--windows-console-mode=hide",
        "--product-name=Sekt0r Auto Jailbreak Tool",
        "--product-version=1.2.0",
        "--file-version=1.2.0",
        "--file-description=PS5 Jailbreak Helper - Self-host Relapse exploit",
        "--copyright=MIT License - Security Research Only",
        "--assume-yes-for-downloads",
        "--include-package=cryptography",
        "--include-package=pooch",
        # Data files to bundle
        "--include-data-file=config.json=config.json",
        "--include-data-dir=assets=assets",
        "--include-data-dir=ps5_jb_helper/i18n=ps5_jb_helper/i18n",
        # Optimizations
        "--remove-output",
        "--lto=yes",
        # Output
        "--output-dir=dist",
        "--output-filename=Sekt0r-Auto-Jailbreak-Tool.exe",
        "ps5_jb_helper.py",
    ]

    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=False)
    return result.returncode

if __name__ == "__main__":
    rc = build()
    sys.exit(rc)