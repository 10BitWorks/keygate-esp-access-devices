# KeyGate ESP Access Devices

Bare-metal Rust firmware for Seeed Studio XIAO ESP32-C6 boards acting as "KeyGates".
Each node reads NFC tags (specifically NTAG 424 DNA with SUN) via a PN532 (I2C) and communicates over Wi-Fi/MQTT.

## Hardware

- **MCU:** Seeed Studio XIAO ESP32-C6 (ESP32-C6, RISC-V, 4MB flash)
- **NFC:** PN532 module via I2C
  - SDA → GPIO2 (D4)
  - SCL → GPIO3 (D5)
  - VCC → 3.3V
  - DIP switches: I2C mode

## Architecture

```
┌──────────────┐     I2C     ┌────────┐
│  XIAO C6     │────────────▶│ PN532  │──── NFC antenna
│  (esp-hal)   │             └────────┘
│              │
│  Wi-Fi/MQTT  │◀───── LAN ─────▶ EMQX Broker & Verifier
└──────────────┘
```

## Building

```bash
# Ensure the RISC-V target is available
rustup target add riscv32imac-unknown-none-elf

# Build
cargo build --release

# Flash (requires espflash)
cargo run --release
```
