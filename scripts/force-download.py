#!/usr/bin/env python3
"""ESP32 download-mode control over USB DTR/RTS — no button dance.

Usage:
  force-download.py [PORT]           — auto: enter ROM download mode and
                                       verify with `espflash board-info`.
  force-download.py [PORT] release   — deassert the strap and tap EN so the
                                       chip boots the APP (run after a
                                       successful flash).

Sequence notes (bench-verified 2026-10-14, official ESP32 DevKitC):

* The two-transistor auto-reset circuit NEUTRALIZES the both-lines-low
  state (EN high, IO0 high). The DTR-assert / RTS-release swap must
  therefore happen BACK-TO-BACK: the EN capacitor (RC ~10 ms) holds the
  chip in reset across the ~1 ms both-low gap. A sleep between the two
  transitions lets EN rise while IO0 is high -> boots the app instead.
  (Verified by ROM banner: `boot:0x3 (DOWNLOAD_BOOT)` + `waiting for
  download` appears only with the atomic swap.)

* IO0 must STAY LOW for the whole espflash session (DTR left asserted,
  -hupcl cleared so the line survives process exit): the cp210x driver
  glitches DTR/RTS on port reconfigure; a glitched EN pulse resets the
  chip and — with IO0 high — lands in the app, killing the stub
  (MemBegin timeout). With IO0 held low the glitch re-enters download
  mode and self-heals, identical to keeping the BOOT button held.
"""
import os, struct, fcntl, termios, time, subprocess, sys

args = [a for a in sys.argv[1:]]
PORT = args[0] if args else "/dev/ttyUSB0"
MODE = args[1] if len(args) > 1 else "auto"
DTR, RTS = 0x002, 0x004
TIOCMBIS, TIOCMBIC = 0x5416, 0x5417


def open_port():
    fd = os.open(PORT, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    attrs = termios.tcgetattr(fd)
    attrs[0] = attrs[1] = 0
    # c_cflag assigned wholesale: HUPCL cleared — lines survive close.
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL | termios.B115200
    attrs[3] = 0
    attrs[4] = attrs[5] = termios.B115200
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    return fd


def mbis(fd, bit):
    fcntl.ioctl(fd, TIOCMBIS, struct.pack("i", bit))


def mbic(fd, bit):
    fcntl.ioctl(fd, TIOCMBIC, struct.pack("i", bit))


if MODE == "release":
    fd = open_port()
    # Idle both lines (IO0 high), then one EN tap -> clean app boot.
    mbic(fd, RTS); mbic(fd, DTR); time.sleep(0.1)
    mbis(fd, RTS); time.sleep(0.1); mbic(fd, RTS)
    os.close(fd)
    print("Strap released; EN tapped — chip boots the app.")
    sys.exit(0)

r = None
for attempt in range(3):
    fd = open_port()
    # Normalize (a previous espflash may exit with lines asserted), then
    # hold the chip in reset: RTS asserted while DTR still high -> EN low.
    mbic(fd, RTS); mbic(fd, DTR); time.sleep(0.1)
    mbis(fd, RTS); time.sleep(0.1)
    # THE SWAP — back-to-back (see module docstring).
    mbis(fd, DTR)
    mbic(fd, RTS)
    time.sleep(0.15)   # EN rises through the RC, IO0 held low
    os.close(fd)       # espflash must own the port alone; DTR stays LOW

    r = subprocess.run(
        ["espflash", "board-info", "--chip", "esp32", "--port", PORT,
         "--before", "no-reset", "-B", "57600"],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode == 0:
        print("Chip in download mode (auto entry, IO0 held).")
        sys.exit(0)
    print(f"entry attempt {attempt + 1} failed, retrying...", file=sys.stderr)
    time.sleep(0.3)

print("Auto entry failed after 3 attempts:",
      ((r.stdout + r.stderr)[-300:] if r else "no attempt ran"), file=sys.stderr)
sys.exit(1)
