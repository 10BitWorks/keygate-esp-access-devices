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

## Pre-flight Checklist (before first deployment)

The firmware compiles and its pure-logic paths are unit-tested, but the full end-to-end path (NFC read -> MQTT -> verifier -> relay) has **never run on hardware**. Work through this list before trusting a board on a live door.

- [ ] **Build secrets supplied.** `WIFI_SSID`, `WIFI_PASS`, `MQTT_USER`, `MQTT_PASSWORD` are compile-time `env!` values with **no defaults** — the build fails without them. Export all four before building.
- [ ] **Broker address confirmed.** `MQTT_HOST` defaults to `10.7.1.106`; verify this is the actual EMQX broker IP (listener `:1883`) and override it if not.
- [ ] **Device onboarded in EMQX.** From the verifier repo, run `cargo run --bin emqx-device -- --device-id <id> --role gate --apply` with `EMQX_API_KEY` set, to create the MQTT credential and ACLs. Without it the broker rejects the connection. Record the one-time password and use it for `MQTT_USER`/`MQTT_PASSWORD`.
- [ ] **Verifier deployed and configured.** It must be running with `MASTER_KEY`, `EMQX_SHARED_SECRET`, MQTT credentials, and `AUTHENTIK_API_TOKEN` set.
- [ ] **EMQX tap rule wired to the verifier.** An EMQX rule on `access/+/auth` must POST to the verifier's `/v1/auth` (container port `8000`, header `x-emqx-secret`). See the verifier `docs/runbook.md`.
- [ ] **Tags provisioned with SUN.** Each NTAG 424 DNA tag needs SUN/SDM enabled and its AES keys registered with the verifier. Non-matching keys cause every tap to be rejected as `bad_cmac`.
- [ ] **PN532 wiring verified against the official pinout.** The firmware uses **GPIO2 (SDA)** and **GPIO3 (SCL)**. The `D4`/`D5` labels in the wiring table above are approximate — confirm which XIAO ESP32-C6 breakout pins actually carry GPIO2/GPIO3 (Seeed's official pinout).
- [ ] **Relay polarity matches the board.** Firmware defaults to active-low; set `RELAY_ACTIVE_LOW=false` for active-high relay modules.
- [ ] **Wi-Fi/VLAN reachability.** The board must join the target SSID and reach the broker on the expected VLAN.
- [ ] **Bench smoke test.** Power one board on a desk; confirm Wi-Fi + MQTT connect, tap a known-good tag, and watch the relay pulse — before mounting it on a door.

## Building and Flashing

The firmware must be compiled for the RISC-V `riscv32imac-unknown-none-elf` target. A builder script is provided.

```bash
# Build the release binary
./run-in-rust-container.sh cargo build --release

# Flash the release binary using espflash
# (assuming the ESP32-C6 is connected over USB serial)
./run-in-rust-container.sh cargo run --release
```
