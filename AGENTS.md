# KeyGate ESP Access Devices — Constraints

## Toolchain
- **Target:** `riscv32imac-unknown-none-elf` — standard bare-metal RISC-V target for ESP32-C6. Classic ESP32 door board uses `xtensa-esp32-none-elf` with `esp` toolchain.
- **Flashing:** Use `espflash` (install via `cargo install espflash`).

## Hardware
- **PN532 Connection:**
  - `board-xiao-c6`: I2C mode. SDA=GPIO2, SCL=GPIO3. Soft re-init recovery only.
  - `board-esp32-devkit-door`: SPI mode (DIPs 1:OFF 2:ON). Documented pins: SCK=GPIO18, MISO=GPIO19, MOSI=GPIO23, CS=GPIO5, IRQ=GPIO4, RSTO=GPIO21 (hardware reset line). Relay on GPIO13. Current bench wiring: SCK=5, MOSI=22, MISO=18, CS=17, RSTO=19 (soft-SPI driver).
- **PN532 Power:** Door module (Elechouse V3 form factor) accepts 3.3–5 V via onboard regulator; bench runs it at VIN (5 V). C6's Waveshare module remains 3.3 V only.
- **Before debugging the door PN532, read `docs/PN532-SPI-NOTES.md`** — root-cause post-mortem, symptom table, and the list of failed experiments not to retry.

## Architecture
- **No LVGL/Display:** This is a headless NFC reader node.
- **No ESP-IDF:** Pure `no_std` with `esp-hal`. No FreeRTOS.
- **Crypto:** Use RustCrypto (`aes`, `cmac`) for NTAG 424 DNA auth. No PSA/mbedtls.

## Wi-Fi & MQTT
- **Wi-Fi Connection:** Connects to fleet SSID — see local `.env` only, never commit.
- **MQTT Broker:** Connect to `broker.10bit` port `1883` (default IP `10.7.1.106`).
- **MQTT Auth Topic:** Publish auth requests to `access/<device_id>/auth`.
- **MQTT Cmd Topic:** Listen for door commands on `access/<device_id>/cmd`.
- **MQTT Presence Topic:** Retained LWT offline and online on `access/<device_id>/presence`.

# Resources

## Piezo Melodies
- Piezo Transducer music generation examples: https://github.com/MoriancumerSouza/arduino-buzzer-songs
- Library of (sound files) examples of nice beep-like notifying sounds: https://www.pond5.com/search?kw=chirp-beep&media=sfx
- Arduino examples: https://github.com/AbhishekGhosh/Arduino-Buzzer-Tone-Codes
- More melodies as beep code: https://github.com/SpaceinvaderOne/Beep-Music-Converter/tree/main/beep_music
