# KeyGate ESP Access Devices — Constraints

## Toolchain
- **Target:** `riscv32imac-unknown-none-elf` — standard bare-metal RISC-V target for ESP32-C6. Classic ESP32 door board uses `xtensa-esp32-none-elf` with `esp` toolchain.
- **Flashing:** Use `espflash` (install via `cargo install espflash`).
- **Bench flashing is buttonless** via `scripts/bench-flash.sh` (auto DTR/RTS
  entry — atomic swap, see `scripts/force-download.py` for the circuit
  truth table; dance-watcher only as fallback). If stub-start failures
  cluster (`MemBegin timeout` in espflash, `Failed to start stub flasher`
  in esptool), the chip is browning out under load — power-cycle the whole
  bench; the script's retry loop absorbs transient stub deaths. esptool
  venv fallback: `/tmp/opencode/esp-venv/bin/python -m esptool` (no-stub
  ROM commands bypass a dead stub entirely).

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

## Firmware loop discipline (hard rules)

- **No line-rate loops, ever.** Every retry/connection loop carries an
  unconditional sleep at the loop top (see `mqtt_runner`'s 1 Hz floor). If a
  loop can outrun its intended cadence when every await returns early, it
  will — and it floods the UART, the broker, and starves sibling tasks.
- Every handshake has a timeout (MQTT connect: 10 s). Zombie sessions and
  CONNACK hangs are failures, not states to wait out.
- Liveness heartbeats (`[pump hb]`, `[mqtt-cycle]`) are load-bearing
  diagnostics: a missing heartbeat in a capture localizes starvation to the
  exact task.
- PN532 readiness is SPI STATREAD polling (`SPIInterface`), bounded by the
  driver's timeouts.
- **The "IRQ" harness wire (GPIO4) must stay DISCONNECTED — live A/B proven
  (2026-10-14, user at bench):** with the wire out the node boots clean and
  the reader works; re-inserting the wire mid-boot on a build that never
  configures GPIO4 kills the PN532 instantly (failure tone). The slot is
  not a benign IRQ output — suspect RSTPDN or a mode pin mislanded by the
  slid 8-pin harness. Before ANY future IRQ usage: continuity-check the
  wire to the actual PN532 IRQ pad with a meter. Never use an unbounded or
  edge-only wait.
- **PN532 `SAMConfig failed (TimeoutAck)`: check the IRQ wire first.** With
  the GPIO4 harness wire connected the module never ACKs (mislanded line —
  see above); disconnect it and the reader comes back. `init_pn532` retries
  3x (ACK-abort resync + 200 ms settle) to self-heal genuine transients.
  Persistent failure across retries with the wire OUT = module wedge (its
  interface mode latches at power-on and the 5 V rail never cycles across
  ESP32 reflashes): pull the module's VIN ~5 s, then reboot. Corroborate
  with the broker log: `pn532 init failed` in `access/<id>/log`, and the
  NfcDown alarm beeps while the reader is down.

## Expected timing (regression baselines — measured 2026-10-14)

**Bench boot logs are archived** under `bench-logs/<commit>-<UTC ts>.log`
(gitignored) by `scripts/bench-flash.sh` and `scripts/bench-capture.py
[duration_s] [--reset]` — every flash and follow-up capture for a build
lands in one attributable file. Consult the matching file before claiming
a regression or re-running an experiment.

Healthy cadences on the ESP32 door bench. A deviation in a capture is a
regression signal, not noise:

- **Boot → bugle: ~5.5 s.** Breakdown: Wi-Fi scan of ~12 APs ≈ 1.9 s → 1 Hz
  connect-loop floor 1.0 s → association ≈ 1.3 s → DHCP ≤ 1.0 s (poll
  granularity) → TCP+CONNACK+subscribes ≈ 0.15 s → bugle on the next ≤500 ms
  piezo tick. (Pre-scan builds booted in ~3 s; scan + floor buy a
  deterministic strongest-BSSID pick and cost ~2.5 s — accepted.)
- **`[pump hb]` every 30 s** (time-based, wall-clock gated). Heartbeats
  stopping while the broker logs `keepalive_timeout` = executor starvation
  or the pump is not being polled — that is a bug, not Wi-Fi.
- **Stable session: zero drops.** Pinned to the strongest AP (~-51 dBm at
  the bench), 5+ minutes showed zero `session poll error`. Drops within
  minutes mean association quality degraded — check the boot line
  `wifi: best xblight AP ... rssi N dBm`.
- **RSSI expectations at the bench:** strongest xblight ≈ -51 dBm (laptop
  survey ≈ -40; PCB antenna difference is normal). Distant cisco units
  measure -73..-86 dBm and produce `AuthenticationExpired` associations —
  the scan-and-pin exists to never pick them. Best-pick below -70 dBm at
  boot = RF problem; investigate placement before firmware.
- **Broker-side truth:** EMQX trace reason `keepalive_timeout` = the device
  went silent on a live TCP socket (starvation). `discarded` = a newer
  connect took the session over (reconnect churn). `tcp_closed` = real link
  loss. Trace lives at `/var/log/emqx/trace_keygate1.log` on 10.7.1.106
  (`emqx ctl trace list`).
