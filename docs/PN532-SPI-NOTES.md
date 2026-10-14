# PN532 SPI on the ESP32 Door Board — Field Notes & Post-Mortem

> **Read this before debugging the door PN532.** Everything below was learned on the bench
> over a ~14-hour session (2026-10-10/11). Several of these experiments cost hours and were
> wrong turns — the "Failed experiments" section exists so nobody retries them.

## TL;DR — the working configuration

- Soft-SPI bit-bang (`DoorSoftSpiDevice` in `src/board.rs`), NOT hardware SPI.
- Bench pins: SCK=GPIO5, MOSI=GPIO22, MISO=GPIO18, CS=GPIO17, RSTO=GPIO19.
  (Documented pinout 18/23/19/5/21 was never re-tested with the working soft-SPI driver —
  revert is planned; pins are proven good, see "Failed experiments".)
- Module VCC on **VIN (5 V)** — onboard regulator; 3.3 V is probably also viable but
  unverified with the fixed firmware (see "3.3 V vs 5 V" under "The module").
- DIP switches **1:OFF, 2:ON = SPI**.
- Timeouts: SAMConfig 500 ms, InListPassiveTarget 3000 ms, InDataExchange 500 ms.
- `sam_configuration(SAMMode::Normal, /* use_irq_pin */ true)` — the IRQ byte must be 0x01.
- Proven chain (commit `c805dfe`): wake → SAMConfig → tag detection (UID/SAK/ATS) →
  ISO-DEP activation → SELECT NDEF app (SW 9000) → SELECT NDEF file (6A82 on blank tag,
  which is correct — blanks have no NDEF file).

## The module

Elechouse V3 **form-factor** PN532 breakout. Clone suspected: RF command latencies run
5–30× slower than Adafruit-class modules (see "Timing measurements"). Identification is by
form factor and behavior; we cannot confirm genuine vs clone.

Facts established empirically:

- **Onboard regulator**: VCC accepts 3.3–5 V; SPI logic levels stay 3.3 V either way.
  The module ran at 5 V for hours with zero damage — an early "3.3 V only, no regulator"
  belief (from the Waveshare constraint) was wrong for this board.
- **3.3 V vs 5 V**: the move to 5 V was motivated by the RF-brownout theory, which is
  dead — the "init OK at 3.3 V but RF dead" symptom is fully explained by the SAMConfig
  IRQ byte (root cause 3), and 5 V empirically did not fix RF. Every confirmed-working
  capture ran at 5 V; 3.3 V with the fixed firmware was never re-tested. On an LDO
  board, 3.3 V input leaves the chip at ~3.0–3.1 V after dropout (in spec, less RF
  headroom); 5 V gives the regulator proper margin. Verdict: 3.3 V almost certainly
  works; 5 V is the slightly safer rail; a 2-minute VCC A/B settles it if it ever
  matters. A BadAck cluster under RF load is the symptom that would implicate supply.
- **DIP switch mapping** (SET0/SET1, silkscreen "0 1", empirically confirmed):
  - `OFF,OFF` = HSU (UART)
  - `ON,OFF` = I2C
  - `OFF,ON` = **SPI**
- **Interface mode latches at power-on / RSTPDN rising edge only.** Pressing the ESP32's
  EN button does NOT relatch. After changing DIPs, power-cycle the module.
- **Back-feed gotcha**: with the bench wired, pulling the module's VCC jumper does NOT
  power it off — the module back-feeds through signal lines (CS/RSTO idle HIGH through
  input protection diodes). The power LED stays lit and no relatch happens. A valid power
  cycle on a wired bench = pull the USB cable and **verify the module LED goes dark**.
- Both PN532 modules in the shop were proven alive via the user's C6 HSU test code; the
  door board's silicon was proven fine by the working soft-SPI driver on "condemned" pins.

## The four stacked root causes (all software/config)

The failure presented as `PN532 init failed` / `TimeoutAck` / `TimeoutResponse` storms
starting 2026-10-10, after the module's VCC was briefly moved to 5 V. The 5 V move was a
red herring — the timing coincidence of a broken build being flashed is what actually
started the outage. Four independent causes, each masking the next:

1. **Hardware-SPI never got a fair trial** (esp-hal `Spi` + `pn532` crate
   `SPIInterface` + our `DoorSpiDevice` wrapper). Symptom: STATUS byte stuck at 0x00
   forever — the module never processed a command frame. At the time this was read as
   "HW-SPI frame delivery broken"; in hindsight every HW-SPI test ran with ALL FOUR root
   causes present: no wake pulse (the crate has none; ours was written only after the
   soft-SPI switch), CS settle/hold delays collapsed by bug 2, no pacing, IRQ byte 0x00,
   and 20 ms timeouts. None of the four fixes is transport-specific (wake = CS-low
   duration, settle/pacing = wrapper delays, IRQ byte and timeouts = protocol layer),
   and Ray's sketch (next section) is an existence proof of hardware SPI on this exact
   module and wiring. HW-SPI is expected to work with the current fixes — it was
   bypassed by bit-banging, not beaten.
2. **`core::hint::spin_loop()` delay loops are deleted by LLVM in release builds** — they
   are side-effect-free hints. Every ms-scale delay (wake pulse, CS settle/hold, 1 ms
   inter-transaction pacing, half-bit timing) silently became a no-op. STATUS polls ran at
   ~121 kHz (~8 µs/poll) instead of ~1 kHz. A diagnostic build "fixed" init purely because
   its serial prints accidentally supplied real milliseconds. Fix: `spin_delay()` using
   `core::hint::black_box(i)` per iteration. **Never trust bare spin loops for timing in
   optimized builds.**
3. **SAMConfig's IRQ byte must be 0x01** (Adafruit sends `01 14 01`). With `use_irq_pin =
   false` (byte 0x00), every bus command (GetGeneralStatus, SAMConfig) completed fine, but
   the first RF command (InListPassiveTarget) ACKed and then never responded —
   `TimeoutResponse` forever. This one byte was the difference between "RF completely
   dead" and "reader works".
4. **The module's RF latencies are slow and variable**: tag-present InListPassiveTarget
   responses measured 240 ms to >3 s (cold re-activation after field release is the slow
   part). Stock timeouts (20/200/50 ms) and even Adafruit's 1000 ms lose the race.
   Current: poll 3000 ms, APDU 500 ms. With a tag held, roughly every other poll still
   exceeds 3 s — a 3–5 s effective detection latency. Acceptable for a door; annoying.

## Symptom → diagnosis table

| Symptom | Meaning | First checks |
|---|---|---|
| `TimeoutAck` at init | Module never saw/processed the command frame | DIPs (SPI = 1:OFF 2:ON); true module power-cycle after DIP change; SCK/MOSI/CS wiring; VCC |
| STATUS byte `0xFF` | MISO not driven — wrong mode, wiring, or dead input | DIPs; MISO line |
| STATUS byte `0x00` forever | Module driving MISO but frame never processed | Frame corrupted on wire (bit order, CS timing); wake pulse missing |
| STATUS byte `0x80` | Ready — module alive and talking | (healthy) |
| `TimeoutResponse` (ACK ok, no response) | RF command died mid-flight | Historically: SAMConfig IRQ byte 0x00; slow RF (hold tag); if permanent on bus commands too, power-cycle module |
| `BadAck` | Module asserted ready but the frame read back as garbage | Mid-recovery/brownout signature; power-cycle module; check supply |
| `NDEF read error: Status(106, 130)` | SW=6A82: NDEF file not found | **Blank/unprovisioned tag** — expected when tapping unwritten NTAG 424s |
| `PN532 init failed` but boot/WiFi/MQTT fine | Init-time only | Same as TimeoutAck row; the firmware runs without NFC rather than hanging |

## Failed experiments — do NOT retry these

- **"GPIO pins fried by the 5 V excursion"** — disproven. GPIO18 (ex-SCK) now reads MISO
  correctly; GPIO19 (ex-MISO, the prime suspect) now drives RSTO fine. Hours were lost to
  MISO remaps, full SPI repins (26/27/22/25), and SPI3 swaps. The board was never damaged.
- **"Devkit die condemned"** — retracted twice. The elimination matrix that "proved" it
  (2 DIP modes × 3 RSTPDN states × 2 SPI peripherals × 2 pin runs, all TimeoutAck) had a
  constant: our firmware. The user's Ray's-C++-read-tags observation was the missing
  control experiment. **Lesson: when a matrix says "everything is broken," suspect the one
  thing you never varied.**
- **"GPIO21 RSTPDN driver died LOW, holding the module in reset"** — disproven (floating
  and 3V3-tied legs both failed identically).
- **"RF burst brownout at 3.3 V"** — moving VCC to 5 V changed nothing (either direction).
  The module has a regulator; RF responses were slow at both rails.
- **`SPIInterfaceWithIrq`** (IRQ pin as readiness signal) — init times out; IRQ signaling
  on this rig is unreliable. STATUS polling works.
- **DIP `ON,OFF` as SPI** — that's I2C on this module family. SPI is `OFF,ON`.
- **EN-press after DIP change as a "relatch"** — does nothing (see latching above).
- **VCC-jumper pull as a "power cycle"** — invalid on a wired bench (back-feed).
- **Bare `spin_loop` timing loops** — optimized out (root cause 2).
- **Adafruit-stock 1000 ms poll timeout** — loses the race on this module ~50% of the time
  with a tag present.

## The control experiment: Ray's Arduino sketch

The user's friend Ray read tags on this exact module and board with stock Arduino code —
`adafruit/Adafruit PN532@^1.3.4`, hardware SPI, documented pins. His sketch (lightly
trimmed) is the control experiment the elimination matrix never had:

```cpp
#include <SPI.h>
#include <Adafruit_PN532.h>

#define PN532_SS 5
Adafruit_PN532 nfc(PN532_SS);          // hardware SPI, SCK=18 MISO=19 MOSI=23 SS=5

void setup() {
    nfc.begin();                        // = wakeup() + getFirmwareVersion()
    uint32_t version = nfc.getFirmwareVersion();
    nfc.SAMConfig();                    // sends mode=normal, IRQ byte = 0x01
}

void loop() {
    uint8_t uid[7]; uint8_t uidLength;
    if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength)) {
        // tag found — relay on GPIO12
    }
    delay(1000);
}
```

What it proves, line by line:

- `SPI.h` + documented pins — **hardware SPI works on this module and wiring** (the
  esp-hal + pn532-crate failure was our stack, not the transport).
- `nfc.begin()` = wakeup + firmware check before `SAMConfig()` — the wake pulse we were
  missing.
- `SAMConfig()` sends IRQ byte **0x01** — root cause 3, verbatim.
- `readPassiveTargetID` = `InListPassiveTarget, MaxTg=1, BrTy=0x00` with a 1000 ms
  timeout — same command, generous timeout.
- No IRQ pin, no RSTPDN wired — both float, and it works (confirms our RSTPDN tests).
- His relay is on **GPIO12 (MTDI strapping pin)** — works because strapping is sampled
  only at reset and his load doesn't pull it low at boot. Our GPIO13 choice remains the
  safer one; don't copy GPIO12.


## Protocol truth (Adafruit_PN532 audit, 2026-10-11)

The `pn532` crate (0.5) diverges from Adafruit_PN532 in ways that matter on this rig:

| Aspect | Adafruit (works) | pn532 crate | Our mitigation |
|---|---|---|---|
| SPI wake | CS LOW ≥2 ms, no clock, before first command | **missing** | `DoorSoftSpiDevice::wake()` (150k spin_delay ≈ 2 ms) |
| Post-write delay | `delay(1)` after command write | none | 1 ms CS-high pacing in `transaction()` |
| Status poll pacing | `delay(10)` between polls | tight loop | ~1–2.4 ms CS-high pacing |
| Read dummy byte | `0xFF` | `0x00` | soft-SPI clocks `0xFF` |
| Bit order | hardware LSB-first | software reversal via `msb-spi` feature | equivalent on wire — verified by write-spy |
| SAMConfig data | `01 14 01` (IRQ=1) | parameterized | **must pass `use_irq_pin = true`** |
| ACK frame | exactly `00 00 FF 00 FF 00` | same | — |

Observed command bytes (write-spy, logical/unreversed): SAMConfig frame
`00 00 FF 05 FB D4 14 01 00 01 16 00`; InListPassiveTarget `... D4 4A 01 00 ...`
(MaxTg=1, BrTy=106 kbps Type A); InDataExchange `D4 40 <tg> <APDU>`. Response prefixes:
`D5 15` (SAMConfig), `D5 4B` (InListPassiveTarget), `D5 41` (InDataExchange).

## Timing measurements (2026-10-11 bench)

- STATUS poll, unpaced (spin-collapsed build): **~8 µs** → ~121 kHz hammer.
- STATUS poll, paced (`spin_delay(75_000)`): **~2.4 ms**.
- ACK after any command: immediate (~1 poll).
- Tag-present InListPassiveTarget response: **240 ms** (at 121 kHz polling) to
  **~890 ms** (at 2.4 ms pacing), sometimes >3 s. No-tag response: well under 1 s.
- APDU (InDataExchange) once target activated: 1–2 polls.
- DHCP on the bench SSID: 20–85 s (multiple retries) — eats serial capture windows;
  MQTT-gate any tap captures (see `scripts/bench-flash.sh`).

### Optimization leads (deliberately not done yet)

- **Poll rate vs module response speed**: the tag response arrived in ~240 ms under 8 µs
  polling but ~890 ms under 2.4 ms polling — as if the clone's firmware progresses its RF
  state machine on SPI activity. If real, there's a pacing sweet spot (try 100–500 µs)
  that halves detection latency. Measure, don't guess.
- **`spin_delay` calibration**: iteration cost is assumed ~2–4 cycles; a cycle-counter
  measurement (or GPIO+scope) would make the constants exact.
- **Hardware SPI retry** — expected to work, not just plausible: every HW-SPI failure is
  explained by the four transport-agnostic bugs, and Ray's sketch (see above) proves the
  transport on this exact module and wiring. Swap `DoorSoftSpiDevice` for the retained
  `DoorSpiDevice` (hardware `Spi`, keep the `spin_delay`-based settle/hold + add wake +
  pacing in its wrapper), keep the current timeouts and IRQ byte. ~30 lines, one bench
  test to confirm; buys a faster bus and frees the CPU during transfers. Residual risk:
  esp-hal multi-op `transaction()` descriptor gaps (audit item 4) — our wrapper holds CS
  across all ops, so the risk is byte-level gaps between `Operation`s at 1 MHz; low.
- Timeout tuning once the above are done: 3000 ms poll → 1500 ms if pacing improves.

## Debug tooling: the `nfc-spy` feature

The wire-level spy from the debug session is kept behind a cargo feature:

```bash
# bench build with spy (write frames, STATUS transitions, response dumps, poll heartbeat)
KEYGATE_CHIP=esp32 ./run-in-rust-container.sh cargo build --release \
    --no-default-features --features chip-esp32,board-esp32-devkit-door,nfc-spy

# production build (spy compiled out)
KEYGATE_CHIP=esp32 ./run-in-rust-container.sh cargo build --release
```

Spy output (all bounded; boot banner shows `SPY` when enabled):

- `[softspi] write[N] … / unreversed:` — outgoing frame bytes, wire + logical order.
- `[softspi] status poll #N -> 0xXX` — STATUS transitions (0x00/0x80/0xFF semantics above).
- `[softspi] frame rd (N B) …` — ACK/response frames fetched via DATAREAD.
- `[nfc] poll #N nbtg=0` — poll heartbeat (loop-alive proof; `nbtg=1` paths print `auth:`).

Cost when enabled: bounded print volume only (counters cap at 400 writes / 400
transitions / 80 frames / 100 heartbeats). When disabled: all spy code is `cfg`'d out —
zero runtime cost, small flash cost for the feature plumbing. Downside of keeping it:
none observed; just don't ship a spy build to a door (the banner tells you).

## Flashing & capture workflow

See `scripts/bench-flash.sh` and the "Interactive Bench Flash" section of the README:
zenity-gated, stub mode + 57600 baud, BOOT dance AFTER "Connecting..." appears
(hold BOOT → tap EN → hold ~5 s → release), raw `cat` capture (espflash monitor hangs on
this CH340), 20–30 s capture windows, MQTT-gated tap captures.

## Open items

- Revert bench pins to the documented pinout (18/23/19/5/21) and re-verify — pins are
  proven good; only the soft-SPI driver has never run on that wiring.
- Full F3 drill needs a provisioned NTAG 424 (SUN written via the verifier) and refreshed
  EMQX credentials — blanks correctly stop at SW 6A82.
- Determine which physical module is on the door (the C6's module was borrowed during
  testing and may not have been returned).

## Serial / flash forensics — invalidated assumptions (2026-10-13/14 bench session)

Assumptions that were tested tonight and **did not survive**, kept here so
nobody re-derives them:

| Assumption | Reality |
|---|---|
| The USB-serial bridge is a CH340 | Never verified. `lsusb` shows the devkit's **on-board CP2102**; the same micro-USB cable was used all night. No external adapter exists. |
| Serial flood byte counts = firmware print rates | **Phantom.** Multiple captures exceeded the 115200 baud physical limit by 10-60x. The adapter/kernel replayed stale buffer content on every reader attach. **Content and ordering are real; volumes are not.** Use the broker (or `emqx ctl clients`) as ground truth. |
| Tag-loop clock "runs fake-fast" (supervisor cooldown passing at kHz rates) | Superseded. Boot-time probe measures `Timer::after(1000ms) = 1000 ms`; loop-tick telemetry showed a sane clock. The "evidence" was phantom flood volume. Treat the app clock as trustworthy. |
| BOOT-dance hold duration matters; late release can kill a started flash | **Unverified either way.** Failures happen at specific stages (MemBegin / ReadReg / FlashDeflData) regardless of hold timing. Release of BOOT does not electrically reset the chip, but a worn BOOT/EN button pair *could* bounce. Keep holds short-ish; treat 8 s as habit, not physics. |
| A failed flash leaves the chip running | No — a failure during connect leaves the chip **in download mode** (next flash needs no dance); a failure **mid-write** corrupts the image → boot-loop or silent brick. Recovery = dance + reflash (ROM bootloader is mask ROM, unbrickable). Proven twice. |
| 20 ms bounded `session.poll()` is harmless | **Invalidated.** Cancelling poll() every iteration starved minimq's pending operations: subscriptions landed minutes late (`subscriptions=0→1→2` over ~3 min) and keepalives were dropped (44 broker `keepalive_timeout` kills in one night) → session-flap cascade. Fixed at **250 ms** (`6126478`). |
| Multi-filter SUBSCRIBE works | **Invalidated.** minimq 0.12's multi-filter encoding is untested upstream; EMQX kills the session with `topic_filter_invalid` on the combined packet. Fixed by two single-filter SUBSCRIBEs (`fb9cdf6`). |
| The EMQX broker "wedged" during the night | **Invalidated.** The ad-hoc probe scripts omitted the MQTT CONNECT fixed header (`0x10`), so the broker correctly dropped every one. The broker was healthy; the restart was unnecessary. |
| The door reader is "slow/weak" | **Invalidated by the owner:** detection is instant with ~0.5-1.5" range when the reader is alive. The real failure mode is the **post-transaction fake-ready wedge**: first tap is seen, then every scan returns clean `NbTg=0` with zero poll errors — invisible to the error-counting supervisor. Now covered by the periodic `GetFirmwareVersion` health probe (`cceff14`). |

### Flash recipes that worked tonight (in order of reliability)

1. Stub + 57600 (`--before no-reset -B 57600 --no-verify`) — most successful.
2. no-stub + 115200 — slower, but its *writes* completed even on the degraded
   link (failures moved to the final MD5 read).
3. `scripts/bench-flash.sh` wraps the zenity-gated retry workflow.

### defmt-espflash experiment (reverted `92d61a4`)

Enabling `esp-hal/defmt` + `esp-println/defmt-espflash` (for minimq internals)
built fine but produced an ELF with **92 loadable segments (ROM max 16)** —
espflash wrote it, the bootloader refused it, board boot-fail-looped
(`esp_image: segment count 92 exceeds max 16`). Reverted in `b2a1ab7`.
If retrying: merge link sections (custom linker script) or use a defmt
transport that doesn't split sections, and verify the image's segment count
with `espflash image-info` **before** flashing.

## Provisioning blocker found (2026-10-14 ~02:00): factory DNA cards ship empty

First live provisioning attempt on a factory-fresh NTAG 424 DNA failed at
`SELECT NDEF application → 6A82 (file not found)`. Root cause: **NTAG 424 DNA
ships DESFire-style empty** — no NDEF application, no files. The provision
sequence (`provision_tag`) assumed a pre-created NDEF app + file 02; the host
mock modeled a personalized card, so the gap never surfaced in tests.

**Resume plan** (well-scoped, ~1-2 h):
1. Add native-command builders: `CREATE_APPLICATION (0xCA)` for AID
   `D2760000850101` (keyset 0x0F, factory key 0) and
   `CREATE_STD_DATA_FILE (0xCD)` for file 02 (size ~128 B, comm plain,
   access EEEE-or-key0) — verify exact settings against the NXP app's
   personalization or schnee/pylibsdm reference flows.
2. In `provision_tag`: attempt `select_ndef`; on `6A82` → run the create path
   (CreateApplication → SelectApplication(0x5A) → CreateStdDataFile) →
   continue with the existing auth/change-key/write/SDM flow.
3. Update the mock card to FACTORY state (no app until created) so the tests
   model reality; keep a "personalized" mock variant for the re-provision path.
4. Bench: `./scripts/arm-provision.sh` → tap → ascending triple → tap again
   → grant → relay.
