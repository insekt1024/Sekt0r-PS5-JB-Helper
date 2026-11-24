#!/usr/bin/env python3
"""
Nuitka build script for SEKT0R AUTO JAILBREAK TOOLKIT (tkinter standalone).
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
        "--product-name=SEKT0R AUTO JAILBREAK TOOLKIT",
        "--product-version=1.2.0",
        "--file-version=1.2.0",
        "--file-description=SEKT0R AUTO JAILBREAK TOOLKIT - Self-host Relapse exploit",
        "--copyright=MIT License - Security Research Only",
        "--assume-yes-for-downloads",
                "--enable-plugin=tk-inter",
                "--tcl-library-dir=C:\\Users\\META PC\\AppData\\Local\\Programs\\Python\\Python314\\tcl",
                "--tk-library-dir=C:\\Users\\META PC\\AppData\\Local\\Programs\\Python\\Python314\\tcl",
                "--include-package=cryptography",
                "--include-package=pooch",
                # Data files to bundle
                "--include-data-file=config.json=config.json",
                "--include-data-dir=assets=assets",
                # Optimizations (NO --lto=yes: Zig backend long-double math link errors)
                "--remove-output",
                # Output
                "--output-dir=dist",
                "--output-filename=SEKT0R-AUTO-JAILBREAK-TOOLKIT.exe",
                "ps5_jb_helper.py",
    ]

    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=False)
    return result.returncode

if __name__ == "__main__":
    rc = build()
    sys.exit(rc)