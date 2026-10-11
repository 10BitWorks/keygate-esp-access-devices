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

if ! zenity --question --title="KeyGate: ESP32 Flashing" \
    --text="Target: $PORT\n\nClick OK, then IMMEDIATELY perform the BOOT dance:\n1. HOLD BOOT button\n2. TAP EN (RST) button once\n3. KEEP HOLDING BOOT for ~5 seconds\n4. RELEASE BOOT\n\nFlashing runs at 57600 baud with stub mode." 2>/dev/null; then
    echo "Flashing cancelled."
    exit 0
fi

FLASHED=1
for i in 1 2 3; do
    echo "=== Flash attempt $i @ 57600 baud (stub mode) ==="
    if timeout 300 espflash flash --chip esp32 --port "$PORT" --before no-reset -B 57600 --no-verify "$ELF"; then
        echo "Flash succeeded on attempt $i!"
        FLASHED=0
        break
    fi
    [ "$i" = 3 ] && break
    if ! zenity --question --title="KeyGate: Retry Flash" \
        --text="Attempt $i missed the bootloader window or timed out.\n\nClick OK, then IMMEDIATELY repeat the BOOT dance:\nHOLD BOOT -> TAP EN -> HOLD ~5s -> RELEASE" 2>/dev/null; then
        echo "Retry cancelled by user."
        break
    fi
done

if [ "$FLASHED" -ne 0 ]; then
    zenity --error --title="KeyGate: Flash Failed" --text="All flash attempts failed." 2>/dev/null || true
    exit 1
fi

if zenity --question --title="KeyGate: Serial Monitoring" \
    --text="Flash complete!\n\nClick OK to capture serial output (20 seconds).\nImmediately after clicking OK, TAP the EN button once to boot the node." 2>/dev/null; then
    stty -F "$PORT" 115200 cs8 -cstopb -parenb raw -echo
    echo "=== Capturing serial from $PORT (20s) ==="
    timeout 20 cat "$PORT" || true
    echo "=== Capture finished ==="
fi
