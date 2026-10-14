#!/usr/bin/env bash
set -euo pipefail

# KeyGate ESP32 Bench Flashing & Capture Helper
# Interactive Zenity-gated workflow optimized for classic ESP32 devkits with CH340 adapters.

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
# Folder is gitignored; curated excerpts get committed into docs/evidence
# by hand when they matter.
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

# Check if chip is already in download/bootloader mode before prompting
is_in_download_mode() {
    timeout 2 espflash board-info --chip esp32 --port "$PORT" --before no-reset -B 57600 >/dev/null 2>&1
}

FLASHED=1

# Automatic boot-mode entry (no buttons): esptool's classic DTR/RTS
# sequence via scripts/force-download.py — bench-proven on this CP2102
# clone (espflash's --before default-reset uses timing it rejects).
# Then flash with --before no-reset (chip already in download mode).
for i in 1 2 3; do
    echo "=== Flash attempt $i @ 57600 baud ==="
    if ! python3 scripts/force-download.py "$PORT"; then
        echo "Auto boot-mode entry failed (attempt $i) — retrying."
        sleep 1
        continue
    fi
    if timeout 300 espflash flash --chip esp32 --port "$PORT" --before no-reset -B 57600 --no-verify --partition-table partitions.csv --erase-parts otadata --target-app-partition ota_0 "$ELF"; then
        echo "Flash succeeded on attempt $i!"
        FLASHED=0
        break
    fi
done

# Last resort: manual BOOT dance (only if auto entry died 3x).
if [ "$FLASHED" -ne 0 ]; then
    if ! zenity --question --timeout=90 --title="KeyGate: Manual BOOT dance" \
        --text="Automatic boot-mode entry failed 3 times.\n\nClick OK, then perform the BOOT dance:\n1. HOLD BOOT button\n2. TAP EN (RST) once\n3. RELEASE BOOT\n(No hold needed — BOOT only has to be low at the moment EN rises.)" 2>/dev/null; then
        echo "Flashing cancelled."
        exit 1
    fi
    if timeout 300 espflash flash --chip esp32 --port "$PORT" --before no-reset -B 57600 --no-verify --partition-table partitions.csv --erase-parts otadata --target-app-partition ota_0 "$ELF"; then
        echo "Flash succeeded (manual dance)!"
        FLASHED=0
    fi
fi

if [ "$FLASHED" -ne 0 ]; then
    zenity --error --title="KeyGate: Flash Failed" --text="All flash attempts failed." 2>/dev/null || true
    exit 1
fi

if zenity --question --title="KeyGate: Serial Monitoring" \
    --text="Flash complete — the node auto-boots (bugle ~5s later).\n\nClick OK to capture serial output (20 seconds)." 2>/dev/null; then
    stty -F "$PORT" 115200 cs8 -cstopb -parenb raw -echo
    echo "=== Capturing serial from $PORT (20s) ==="
    timeout 20 cat "$PORT" || true
    echo "=== Capture finished ==="
fi
