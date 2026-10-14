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

# Phase 1 — fully automatic (no buttons). scripts/force-download.py enters
# download mode via the esptool DTR/RTS sequence (atomic DTR/RTS swap —
# verified by ROM banner boot:0x3 DOWNLOAD_BOOT on this official DevKitC;
# the earlier failures were a sleep between the swaps, not hardware).
for i in 1 2 3; do
    echo "=== Flash attempt $i (automatic boot-mode entry) ==="
    if python3 scripts/force-download.py "$PORT" \
       && timeout 300 espflash flash --chip esp32 --port "$PORT" --before no-reset -B 57600 --no-verify --partition-table partitions.csv --erase-parts otadata --target-app-partition ota_0 "$ELF"; then
        echo "Flash succeeded on attempt $i (buttonless)!"
        FLASHED=0
        break
    fi
    sleep 1
done

# Phase 2 (fallback) — FLASH-WHEN-READY watcher: zero coordination. Retries
# espflash every few seconds; whenever a manual BOOT dance happens (HOLD
# BOOT -> TAP EN -> RELEASE, hold not required), the next attempt catches
# it. Used only if automatic entry failed 3x (e.g. USB line stuck).
if [ "$FLASHED" -ne 0 ]; then
    ARM_SECONDS="${KEYGATE_ARM_SECONDS:-420}"
    echo "=== Auto entry failed — FLASH-WHEN-READY armed for ${ARM_SECONDS}s ==="
    echo "    Do the BOOT dance at ANY time: HOLD BOOT -> TAP EN -> RELEASE."
    command -v notify-send >/dev/null && notify-send "KeyGate flasher armed" \
        "Auto entry failed. Do the BOOT dance any time in the next $((ARM_SECONDS / 60)) min." || true
    if [ -n "${DISPLAY:-}" ] && command -v zenity >/dev/null; then
        zenity --info --timeout=20 --title="KeyGate: flasher armed" \
            --text="Automatic entry failed.\n\nWatcher armed for $((ARM_SECONDS / 60)) min.\nDo the BOOT dance at ANY time:\nHOLD BOOT -> TAP EN -> RELEASE" 2>/dev/null || true &
    fi

    DEADLINE=$(( $(date +%s) + ARM_SECONDS ))
    ATTEMPT=0
    while [ "$(date +%s)" -lt "$DEADLINE" ]; do
        ATTEMPT=$((ATTEMPT + 1))
        if OUT=$(timeout 120 espflash flash --chip esp32 --port "$PORT" --before no-reset -B 57600 --no-verify --partition-table partitions.csv --erase-parts otadata --target-app-partition ota_0 "$ELF" 2>&1); then
            echo "$OUT" | rtk grep -vE "boot:|esp_image|ets Jul|rst:0x1|configsip|mode:DIO|load:|ho 8|entry |clk_drv|d_drv|SPIWP" || true
            echo "Flash succeeded on watcher attempt $ATTEMPT!"
            FLASHED=0
            break
        fi
        sleep 3
    done
fi

if [ "$FLASHED" -ne 0 ]; then
    echo "All flash paths failed."
    zenity --error --timeout=30 --title="KeyGate: Flash Failed" \
        --text="Automatic entry failed and no BOOT dance was detected." 2>/dev/null || true
    exit 1
fi

# Entry left IO0 held low (glitch self-heal, see force-download.py); release
# the strap and tap EN so the freshly flashed app boots before the capture.
python3 scripts/force-download.py "$PORT" release || true

if zenity --question --title="KeyGate: Serial Monitoring" \
    --text="Flash complete — the node auto-boots (bugle ~5s later).\n\nClick OK to capture serial output (20 seconds)." 2>/dev/null; then
    stty -F "$PORT" 115200 cs8 -cstopb -parenb raw -echo
    echo "=== Capturing serial from $PORT (20s) ==="
    timeout 20 cat "$PORT" || true
    echo "=== Capture finished ==="
fi
