#!/usr/bin/env python3

"""
clippy.py

Continuously displays clipboard contents on Linux/X11 systems.

Supports:
- Regular clipboard (CTRL+C / CTRL+V)
- Primary selection (middle-click paste selection)

Requirements:
    pip install pyperclip

External tools required on Kali:
    xclip

Install:
    sudo apt install xclip
"""

import subprocess
import time
import pyperclip
from datetime import datetime


POLL_INTERVAL = 0.5


def get_primary_selection():
    """
    Reads the X11 PRIMARY selection (middle-click buffer).
    """
    try:
        result = subprocess.run(
            ["xclip", "-o", "-selection", "primary"],
            capture_output=True,
            text=True,
            timeout=1
        )

        if result.returncode == 0:
            return result.stdout.strip()

    except Exception:
        pass

    return ""


def timestamp():
    return datetime.now().strftime("%H:%M:%S")


def main():
    print("=" * 70)
    print(" Clipboard Monitor")
    print("=" * 70)
    print("Watching:")
    print("  • CLIPBOARD (Ctrl+C / Ctrl+V)")
    print("  • PRIMARY   (mouse selection / middle-click paste)")
    print()
    print("Press Ctrl+C to quit.")
    print("=" * 70)

    last_clipboard = None
    last_primary = None

    while True:
        try:
            # Standard clipboard
            clipboard = pyperclip.paste()

            # Middle-click/X11 selection buffer
            primary = get_primary_selection()

            if clipboard != last_clipboard:
                print(f"\n[{timestamp()}] CLIPBOARD")
                print("-" * 70)
                print(clipboard if clipboard else "<empty>")
                last_clipboard = clipboard

            if primary != last_primary:
                print(f"\n[{timestamp()}] PRIMARY")
                print("-" * 70)
                print(primary if primary else "<empty>")
                last_primary = primary

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print("\nExiting.")
            break

        except Exception as e:
            print(f"\nError: {e}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
