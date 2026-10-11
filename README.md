# KeyGate ESP Access Devices

[![CI](https://github.com/10BitWorks/keygate-esp-access-devices/actions/workflows/ci.yml/badge.svg)](https://github.com/10BitWorks/keygate-esp-access-devices/actions/workflows/ci.yml)

Bare-metal Rust firmware for Seeed Studio XIAO ESP32-C6 nodes and classic ESP32 door prototype boards acting as "KeyGates".
Each node reads NFC tags (specifically NTAG 424 DNA with SUN) via a PN532 reader and communicates over Wi-Fi/MQTT with an EMQX broker and verifier service.

## Chip × Board Matrix

Firmware features select both the target SoC (`chip-*`) and the board wiring configuration (`board-*`).

| Chip Feature \ Board Feature | `board-xiao-c6` | `board-esp32-devkit-door` |
|---|---|---|
| `chip-esp32c6` (RISC-V) | **Valid** (Default) | *Invalid* |
| `chip-esp32` (Xtensa) | *Invalid* | **Valid** |

Default features in `Cargo.toml` are `["chip-esp32c6", "board-xiao-c6"]`.

### Adding a Third Board

Adding a new board target requires two additions:
1. Declare a new Cargo feature in `Cargo.toml` (e.g. `board-custom = []`).
2. Implement a `#[cfg(feature = "board-custom")]` configuration block in `src/board.rs` defining pin mappings, bus construction, and the returned `Setup<I>` struct.

## Hardware Wiring

### Seeed Studio XIAO ESP32-C6 (`board-xiao-c6`)

- **MCU:** Seeed Studio XIAO ESP32-C6 (ESP32-C6, RISC-V, 4 MB flash)
- **NFC:** PN532 module via I2C (100 kHz)
  - SDA → GPIO2
  - SCL → GPIO3
  - VCC → 3.3V
  - DIP switches: I2C mode
- **Relay Strike:** GPIO1 (active-low default)
- **Status LED:** GPIO15 (active-low default)
- **Hardware Reset:** None wired. Lockup recovery uses soft re-initialization.

### Classic ESP32 DevKit Door (`board-esp32-devkit-door`)

- **MCU:** Classic ESP32 DevKit (ESP32, Xtensa Dual Core, 4 MB flash)
- **NFC:** PN532 module via SPI (1 MHz, Mode 0)
  - SCK → GPIO18
  - MISO → GPIO19
  - MOSI → GPIO23
  - CS → GPIO5
  - IRQ → GPIO4 (pull-up enabled)
  - RSTO → GPIO21 (hardware reset line connected to PN532 RSTPDN)
  - DIP switches: SPI mode
- **Relay Strike:** GPIO13 (active-low default)
  - *Design note:* Relay uses GPIO13 rather than D12. GPIO12 is the ESP32 MTDI strapping pin controlling internal SPI flash voltage (VDD_SDIO 3.3V vs 1.8V) at boot. Connecting relay circuitry or pull-downs to GPIO12 risks boot failure and flash read errors.
- **Status LED:** GPIO2 (onboard LED, active-low default)

### PN532 Lockup Supervisor & RSTO Recovery

Field deployments under sustained heat can experience PN532 transport lockups where the reader stops acknowledging bus transactions.
- **Door board recovery:** The supervisor monitors tag poll results. When 8 consecutive poll failures occur (~200 ms of transport/protocol errors), the supervisor pulses RSTO (GPIO21) low for 10 ms, waits 100 ms for reader boot, and runs `soft_reinit()` to restore SAM configuration. A 5-second cooldown re-arms subsequent hardware reset cycles to prevent bus thrashing.
- **XIAO ESP32-C6 recovery:** The XIAO board lacks a dedicated hardware reset line (`reader_reset = None`). When 8 consecutive errors occur, it logs that no hardware reset line is wired and performs `soft_reinit()` on the active I2C interface.

## Build-time Environment Variables

Configuration is injected at compile-time via `env!` and `option_env!`.

| Variable | Requirement | Default | Description |
|---|---|---|---|
| `WIFI_SSID` | **Mandatory** | - | Wi-Fi network SSID (see local `.env` only, never commit) |
| `WIFI_PASS` | **Mandatory** | - | Wi-Fi network password (see local `.env` only, never commit) |
| `MQTT_USER` | **Mandatory** | - | MQTT authentication username |
| `MQTT_PASSWORD` | **Mandatory** | - | MQTT authentication password |
| `MQTT_HOST` | Optional | `10.7.1.106` | MQTT broker hostname or IP |
| `MQTT_PORT` | Optional | `1883` | MQTT broker port |
| `DEVICE_ID` | Optional | `keygate1` | Device identifier for MQTT topic paths |
| `RELAY_ACTIVE_LOW` | Optional | `true` | Toggle relay active-low polarity |

## Continuous Integration (CI)

Public CI runs on every push and pull request via GitHub Actions.
The workflow is strictly compile-only and carries no secrets or build artifacts:
- **`host-tests`:** Runs unit and protocol test suites (`cargo test --lib`).
- **`firmware-c6`:** Compiles the ESP32-C6 firmware binary for `riscv32imac-unknown-none-elf` with dummy build credentials.
- **`firmware-esp32`:** Compiles the classic ESP32 door binary for `xtensa-esp32-none-elf` using the `esp` toolchain and dummy build credentials.

## Pre-flight Checklist (before first deployment)

The firmware compiles and its pure-logic paths are unit-tested. Verify the hardware and network checklist before mounting a board on an active door:

- [ ] **Build secrets supplied.** `WIFI_SSID`, `WIFI_PASS`, `MQTT_USER`, `MQTT_PASSWORD` are compile-time `env!` values with **no defaults**. Export them or maintain a local `.env` file before building.
- [ ] **Broker address and VLAN routing confirmed.** `MQTT_HOST` defaults to `10.7.1.106:1883`. Verify that the fleet SSID's assigned VLAN can reach `10.7.1.106:1883` while the untrusted members VLAN remains blocked. Note that EMQX broker authentication is currently disabled; anonymous access from VLAN 7 will be removed in an upcoming network maintenance window.
- [ ] **Verifier deployed and configured.** The verifier service must be reachable with `MASTER_KEY`, `EMQX_SHARED_SECRET`, MQTT credentials, and `AUTHENTIK_API_TOKEN` configured.
- [ ] **EMQX tap rule wired to the verifier.** An EMQX rule on `access/+/auth` must POST to the verifier's `/v1/auth` endpoint (container port `8000`, header `x-emqx-secret`). See the verifier runbook.
- [ ] **Tags provisioned with SUN.** Each NTAG 424 DNA tag requires SUN/SDM mirroring enabled with AES keys registered in the verifier.
- [ ] **PN532 wiring verified against board pinouts.**
  - XIAO ESP32-C6: GPIO2 (SDA), GPIO3 (SCL).
  - ESP32 DevKit Door: SCK (GPIO18), MISO (GPIO19), MOSI (GPIO23), CS (GPIO5), IRQ (GPIO4), RSTO (GPIO21).
- [ ] **Relay polarity matches the hardware module.** Firmware defaults to active-low (`RELAY_ACTIVE_LOW=true`). Set `RELAY_ACTIVE_LOW=false` for active-high driver boards.
- [ ] **Bench smoke test.** Power the board on a bench, verify Wi-Fi and MQTT connectivity, tap a known SUN tag, and verify relay pulse before field installation.

## Building and Flashing

Build commands use the local container wrapper script `run-in-rust-container.sh`.

### Building for Seeed Studio XIAO ESP32-C6 (Default)

Target: `riscv32imac-unknown-none-elf`

```bash
# Debug build
./run-in-rust-container.sh cargo build

# Release build
./run-in-rust-container.sh cargo build --release

# Flash via espflash over USB serial
./run-in-rust-container.sh cargo run --release
```

### Building for Classic ESP32 Door Board

Target: `xtensa-esp32-none-elf`

```bash
# Debug build
KEYGATE_CHIP=esp32 ./run-in-rust-container.sh cargo build

# Release build
KEYGATE_CHIP=esp32 ./run-in-rust-container.sh cargo build --release
```

When `KEYGATE_CHIP=esp32` is set, `run-in-rust-container.sh` automatically:
- Sets `RUSTUP_TOOLCHAIN=esp`.
- Injects `--target xtensa-esp32-none-elf` and `-Zbuild-std=core,alloc`.
- Injects `--no-default-features --features chip-esp32,board-esp32-devkit-door`.
- Sources `.env` first, followed by `.env.esp32` if present.

### One-Time Xtensa Toolchain Bootstrap

Classic ESP32 uses the Xtensa architecture (`xtensa-esp32-none-elf`), which requires the Espressif `esp` Rust fork installed via `espup`. To bootstrap the Xtensa toolchain for the container:

```bash
# 1. Install espup into the shared cargo/bin inside the container
./run-in-rust-container.sh cargo install espup

# 2. Install the Xtensa toolchain and GCC into the shared rustup/ directory
./run-in-rust-container.sh bash -c 'export PATH="$HOME/.cargo/bin:$PATH"; espup install --targets esp32'

# 3. Verify that the 'esp' toolchain is registered
./run-in-rust-container.sh rustup toolchain list
```
