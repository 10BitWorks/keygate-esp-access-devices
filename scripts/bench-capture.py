#!/usr/bin/env python3
"""Bench serial capture, archived under bench-logs/ (gitignored).

Usage: scripts/bench-capture.py [duration_s] [--reset]

Captures /dev/ttyUSB0 for `duration_s` seconds (default 30), teeing every
line to stdout AND to the current bench session file:
  bench-logs/<commit>-<UTC timestamp>.log
appending to the newest session file if one was touched within the last
hour (so flash + follow-up captures land in one attributable file), else
creating a new one named by the current commit.

`--reset` pulses the esptool DTR/RTS sequence first (clean boot capture).
"""

import os
import sys
import glob
import time
import termios
import subprocess
import fcntl
import struct

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGDIR = os.path.join(REPO, "bench-logs")
PORT = "/dev/ttyUSB0"

duration = 30.0
do_reset = "--reset" in sys.argv
for a in sys.argv[1:]:
    if a.isdigit():
        duration = float(a)


def git_sha() -> str:
    try:
        return (
            subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=True,
            )
            .stdout.strip()
            or "nogit"
        )
    except Exception:
        return "nogit"


def session_file() -> str:
    os.makedirs(LOGDIR, exist_ok=True)
    logs = sorted(glob.glob(os.path.join(LOGDIR, "*.log")), key=os.path.getmtime)
    now = time.time()
    if logs and now - os.path.getmtime(logs[-1]) < 3600:
        return logs[-1]
    return os.path.join(
        LOGDIR, f"{git_sha()}-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}.log"
    )


fd = os.open(PORT, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
attrs = termios.tcgetattr(fd)
attrs[0] = attrs[1] = 0
attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL | termios.B115200
attrs[3] = 0
attrs[4] = termios.B115200
attrs[5] = termios.B115200
termios.tcsetattr(fd, termios.TCSANOW, attrs)

if do_reset:
    TIOCM_DTR, TIOCM_RTS = 0x002, 0x004
    TIOCMBIS, TIOCMBIC = 0x5416, 0x5417
    d, r = struct.pack("i", TIOCM_DTR), struct.pack("i", TIOCM_RTS)
    fcntl.ioctl(fd, TIOCMBIC, d)
    fcntl.ioctl(fd, TIOCMBIS, r)
    time.sleep(0.15)
    fcntl.ioctl(fd, TIOCMBIC, r)

path = session_file()
header = f"=== bench-capture {time.strftime('%FT%TZ', time.gmtime())} sha={git_sha()} reset={do_reset} ==="
with open(path, "a") as f:
    f.write(header + "\n")
print(header)
print(f"archiving to {path}", flush=True)

t0 = time.time()
buf = b""
logfile = open(path, "a")
while time.time() - t0 < duration:
    try:
        c = os.read(fd, 65536)
        if c:
            text = c.decode("utf-8", errors="replace")
            logfile.write(text)
            logfile.flush()
            sys.stdout.write(text)
            sys.stdout.flush()
            buf = (buf + c)[-200:]
    except BlockingIOError:
        pass
    time.sleep(0.02)
logfile.close()
os.close(fd)
print(f"\n=== capture finished ({duration:.0f}s) -> {path} ===")
