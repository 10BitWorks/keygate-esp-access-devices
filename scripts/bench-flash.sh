#!/usr/bin/env bash
set -euo pipefail

# KeyGate ESP32 Bench Flashing & Capture Helper
#
# FLASH PATH: esptool --no-stub (ROM commands only). The stub path
# (espflash, esptool with stub) dies on this bench — stub start / MemBegin
# timeouts cluster regardless of entry method (button dance, DTR/RTS auto,
# in-process), while ROM-only commands (erase/write/verify) have succeeded
# in every session. Cost: ~4-5 min per flash at 57600 baud. Benefit: fully
# unattended, no BOOT dance, no stub.
# scripts/force-download.py 'release' boots the app afterwards (the write
# leaves the chip in download mode).

export PATH="$HOME/.guix-profile/bin:$PATH"
export DISPLAY="${DISPLAY:-:0}"

cd "$(dirname "$0")/.."
ELF="target/xtensa-esp32-none-elf/release/keygate-esp-access-devices"

if [ ! -f "$ELF" ]; then
    echo "Error: Release binary not found at $ELF"
    echo "Run: KEYGATE_CHIP=esp32 ./run-in-rust-container.sh cargo build --release"
    exit 1
fi

# Archive the whole session (flash + boot capture) under bench-logs/, named
# by the commit under test, so results from any build stay attributable.
SHA=$(git rev-parse --short HEAD 2>/dev/null || echo nogit)
mkdir -p bench-logs
LOG="bench-logs/${SHA}-$(date -u +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

PORT=""
for probe in 1 2 3; do
    PORT=$(ls /dev/ttyUSB* 2>/dev/null | head -1 || true)
    [ -n "$PORT" ] && break
    if ! zenity --question --title="KeyGate: Serial Port Scan" \
        --text="No /dev/ttyUSB* device detected.\n\nPlease connect/re-seat the USB cable.\nClick OK to retry scan." 2>/dev/null; then
        echo "Aborted by user."
        exit 0
    fi
    sleep 1
done

if [ -z "$PORT" ]; then
    zenity --error --title="KeyGate: Error" --text="No serial port detected. Aborting." 2>/dev/null || true
    exit 1
fi

echo "Target port: $PORT"
echo "Session log: $LOG (commit $SHA)"

# esptool venv (self-provisioning; uv is in the guix profile).
ESPTOOL_VEN="${ESPTOOL_VEN:-/tmp/opencode/esp-venv}"
if ! "$ESPTOOL_VEN/bin/python" -m esptool version >/dev/null 2>&1; then
    echo "Provisioning esptool venv at $ESPTOOL_VEN..."
    uv venv "$ESPTOOL_VEN"
    uv pip install --python "$ESPTOOL_VEN/bin/python" esptool
fi
ESP="$ESPTOOL_VEN/bin/python -m esptool"

# Build the app image (same header espflash produced: DIO / 40 MHz / 4 MB).
rm -f /tmp/keygate-app.bin
echo "=== Building app image (elf2image) ==="
$ESP --chip esp32 elf2image --flash-mode dio --flash-freq 40m --flash-size 4MB \
    --output /tmp/keygate-app.bin "$ELF" || { echo "elf2image failed"; exit 1; }

FLASHED=1
for i in 1 2 3; do
    echo "=== Flash attempt $i (esptool no-stub, ~4-5 min) ==="
    if timeout 120 $ESP --chip esp32 --port "$PORT" --baud 57600 \
            --before default-reset --after no-reset --no-stub \
            erase-region 0xd000 0x2000 \
       && timeout 900 $ESP --chip esp32 --port "$PORT" --baud 57600 \
            --before default-reset --after no-reset --no-stub \
            write-flash 0x10000 /tmp/keygate-app.bin; then
        echo "Flash succeeded on attempt $i (no-stub)!"
        FLASHED=0
        break
    fi
    echo "attempt $i failed — retrying."
    sleep 2
done

if [ "$FLASHED" -ne 0 ]; then
    zenity --error --timeout=30 --title="KeyGate: Flash Failed" \
        --text="No-stub flash failed 3 times. Power-cycle the bench and retry." 2>/dev/null || true
    exit 1
fi

# The write leaves the chip in download mode (IO0 strap held); release and
# tap EN so the freshly flashed app boots before the capture.
python3 scripts/force-download.py "$PORT" release || true

if zenity --question --title="KeyGate: Serial Monitoring" \
    --text="Flash complete — the node auto-boots (bugle ~5s later).\n\nClick OK to capture serial output (20 seconds)." 2>/dev/null; then
    stty -F "$PORT" 115200 cs8 -cstopb -parenb raw -echo
    echo "=== Capturing serial from $PORT (20s) ==="
    timeout 20 cat "$PORT" || true
    echo "=== Capture finished ==="
fi
