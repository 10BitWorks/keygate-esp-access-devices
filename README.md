# KeyGate ESP Access Devices

Bare-metal Rust firmware for Seeed Studio XIAO ESP32-C6 boards acting as "KeyGates".
Each node reads NFC tags (specifically NTAG 424 DNA with SUN) via a PN532 (I2C) and communicates over Wi-Fi/MQTT.

## Hardware Wiring

- **MCU:** Seeed Studio XIAO ESP32-C6 (ESP32-C6, RISC-V, 4MB flash)
- **NFC:** PN532 module via I2C
  - SDA → GPIO2 (D4)
  - SCL → GPIO3 (D5)
  - VCC → 3.3V
  - DIP switches: I2C mode
- **Relay Strike:** GPIO1 (active-low default)
- **Status LED:** GPIO15 (active-low default)

## Build-time Environment Variables

Configuration is injected at compile-time via `env!` and `option_env!`.

| Variable | Requirement | Default | Description |
|---|---|---|---|
| `WIFI_SSID` | **Mandatory** | - | Wi-Fi network SSID |
| `WIFI_PASS` | **Mandatory** | - | Wi-Fi network password |
| `MQTT_USER` | **Mandatory** | - | MQTT authentication username |
| `MQTT_PASSWORD` | **Mandatory** | - | MQTT authentication password |
| `MQTT_HOST` | Optional | `10.7.1.106` | MQTT broker hostname or IP |
| `MQTT_PORT` | Optional | `1883` | MQTT broker port |
| `DEVICE_ID` | Optional | `keygate1` | Device identifier for MQTT topic paths |
| `RELAY_ACTIVE_LOW` | Optional | `true` | Toggle relay active-low polarity |

## Device Onboarding (EMQX)

To onboard a device, run the `emqx-device` tool from the verifier repo to create EMQX REST API credentials and ACLs:

```bash
# Set required EMQX REST credentials first
export EMQX_API_KEY="your-api-key:your-api-secret" 

# Provision the device (creates credentials and ACL rules)
cargo run --bin emqx-device -- --device-id <id> --role gate --apply
```

## Architecture

```
┌──────────────┐     I2C     ┌────────┐
│  XIAO C6     │────────────▶│ PN532  │──── NFC antenna
│  (esp-hal)   │             └────────┘
│              │
│  Wi-Fi/MQTT  │◀───── LAN ─────▶ EMQX Broker & Verifier
└──────────────┘
```

## Building and Flashing

The firmware must be compiled for the RISC-V `riscv32imac-unknown-none-elf` target. A builder script is provided.

```bash
# Build the release binary
./run-in-rust-container.sh cargo build --release

# Flash the release binary using espflash
# (assuming the ESP32-C6 is connected over USB serial)
./run-in-rust-container.sh cargo run --release
```
