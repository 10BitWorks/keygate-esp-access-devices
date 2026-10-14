#!/usr/bin/env python3
"""Force the ESP32 into the ROM download mode over USB — no button dance.

Reproduces esptool's classic DTR/RTS entry sequence (espflash's
--before default-reset uses different timing that this CP2102 clone
rejects; this sequence is bench-proven 2026-10-14):

  1. RTS asserted   -> EN low   (chip held in reset)
  2. DTR asserted   -> IO0 low  (boot strap latched)
  3. RTS released   -> chip boots with IO0 low -> ROM bootloader
  4. DTR released

With 100 ms settles (cheap CP2102 clones propagate USB->GPIO slowly).

Exit 0 = download mode verified via `espflash board-info`.
"""
import os, struct, fcntl, termios, time, subprocess, sys

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
DTR, RTS = 0x002, 0x004
TIOCMBIS, TIOCMBIC = 0x5416, 0x5417

fd = os.open(PORT, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
attrs = termios.tcgetattr(fd)
attrs[0] = attrs[1] = 0
attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL | termios.B115200
attrs[3] = 0
attrs[4] = attrs[5] = termios.B115200
termios.tcsetattr(fd, termios.TCSANOW, attrs)


def mbis(bit):
    fcntl.ioctl(fd, TIOCMBIS, struct.pack("i", bit))


def mbic(bit):
    fcntl.ioctl(fd, TIOCMBIC, struct.pack("i", bit))


# Normalize: a previous espflash process may exit with DTR/RTS asserted;
# the sequence below assumes both lines idle first.
mbic(RTS); mbic(DTR); time.sleep(0.2)

r = None
for attempt in range(3):
    mbic(RTS); time.sleep(0.05)  # idle
    mbis(RTS); time.sleep(0.1)   # EN low: hold in reset
    mbis(DTR); time.sleep(0.1)   # IO0 low while held
    mbic(RTS); time.sleep(0.15)  # boot with IO0 low -> download mode; ROM settles
    mbic(DTR)
    time.sleep(0.1)

    r = subprocess.run(
        ["espflash", "board-info", "--chip", "esp32", "--port", PORT,
         "--before", "no-reset", "-B", "57600"],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode == 0:
        print("Chip in download mode (auto entry).")
        sys.exit(0)
    # espflash's verify connection may itself disturb the lines; re-normalize.
    try:
        mbic(RTS); mbic(DTR)
    except OSError:
        pass
    time.sleep(0.3)

print("Auto entry failed after 3 attempts:",
      ((r.stdout + r.stderr)[-300:] if r else "no attempt ran"), file=sys.stderr)
sys.exit(1)
