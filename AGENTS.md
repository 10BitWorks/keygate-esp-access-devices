# KeyGate ESP Access Devices — Constraints

## Toolchain
- **Target:** `riscv32imac-unknown-none-elf` — the standard bare-metal RISC-V target for ESP32-C6.
- **Flashing:** Use `espflash` (install via `cargo install espflash`).

## Hardware
- **PN532 Connection:** I2C mode. SDA=GPIO2, SCL=GPIO3.
- **PN532 Power:** 3.3V only (same constraint as Waveshare board).

## Architecture
- **No LVGL/Display:** This is a headless NFC reader node.
- **No ESP-IDF:** Pure `no_std` with `esp-hal`. No FreeRTOS.
- **Crypto:** Use RustCrypto (`aes`, `cmac`) for NTAG 424 DNA auth. No PSA/mbedtls.

## Wi-Fi & MQTT
- **Wi-Fi Connection:** Connects to SSID `"10bitworks"` with password `"10bitrocks"`.
- **MQTT Broker:** Connect to `broker.10bit` port `1883`.
- **MQTT Auth Topic:** Publish auth requests to `access/<device_id>/auth`.
- **MQTT Cmd Topic:** Listen for door commands on `access/<device_id>/cmd`.
- **MQTT Presence Topic:** Retained LWT offline and online on `access/<device_id>/presence`.
