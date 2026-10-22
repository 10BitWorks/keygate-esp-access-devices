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
- **`SPIInterfaceWithIrq`** (the crate's built-in IRQ polling, architecture
  A) — init times out; IRQ signaling on this rig is unreliable *through that
  path* (it is a non-blocking `is_low()` read inside the crate's tight
  `while` loop — no confirm step, no sleeping). STATUS polling works. See
  §6 for the 2026-10-22 meter verification and the architecture-C
  implementation that supersedes this entry.
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

### Refinement (2026-10-14 02:30): the 6A82 is narrower than "factory ships empty"

NXP AN12196 + docs.rs/ntag424 + nfcutils all agree factory DNA cards **do**
have the NDEF app and file 02 (256 B, free RW, keys all-zero). So the live
`sequence error: Status(0x6A82)` is from a specific step, prime suspect:
**the NDEF file SELECT**. AN12196 selects files by ISO file ID — NDEF = `E104`,
CC = `E103`, proprietary = `E105` — while our sequence selects file number `02`
(`SELECT_NDEF_FILE_02_APDU` in `src/ntag424.rs`). Switched file select to `0xE1, 0x04`
in commit `d1b570f`.

## Architectural Breakthroughs & Flash Forensics (2026-10-14 ~04:00)

### 1. Decoupled NFC and Network Runners (Full Offline Support)
- Previously, NFC tag polling was trapped inside the synchronous MQTT session loop. Any Wi-Fi drop, DHCP negotiation delay, or broker reconnection blocked card reading completely.
- Converted `node::run` to execute two concurrent async tasks via `embassy_futures::join::join`:
  - `nfc_runner`: Dedicated task with ownership of the PN532. Polls every ~15-20 ms, handles card detection, immediate audible feedback, NDEF parsing, and enqueues auth requests to `AUTH_OUTBOUND`. Operates 100% offline without network connectivity.
  - `mqtt_runner`: Dedicated task managing Wi-Fi, DHCP, MQTT session (`session.poll()`), and publishing queued auth and claim payloads.
- Network latency or disconnects now have zero impact on reader responsiveness.

### 2. Smooth Tag Detection & Blank Card Resilience
- Aligned `nfc::poll_tag` with the proven Waveshare C6 (`xiao-c6`) architecture: fast 200 ms non-blocking poll returning `Option<TagInfo>`.
- Removed `ResetPolicy` error-counting from normal polling: RF timeouts when no tag is present are normal and no longer cause hardware resets.
- Added `nfc::cycle_rf_field(pn)` after card reads: power-cycles passive tags resting on the antenna back to ISO 14443-3 `Idle`, preventing ISO-DEP lockup and allowing clean debouncing on repeated taps.
- Blank/unwritten cards (`nlen == 0` / `InvalidLength`) are handled gracefully as unwritten tags without triggering errors or crashes.

### 3. Flash Bootloader Partition Table Gotcha (`otadata`)
- The ESP32 partition table defines `ota_0` (offset `0x10000`) and `ota_1` (offset `0x1E0000`).
- If `otadata` (`0xD000`, 8 KB) holds active partition sequence pointing to `ota_1`, the ESP-IDF bootloader boots `ota_1` regardless of `espflash` writing new binaries to `0x10000` (`ota_0`).
- Fix: `scripts/bench-flash.sh` explicitly passes `--partition-table partitions.csv --erase-parts otadata --target-app-partition ota_0`. Erasing `otadata` forces the bootloader to always boot `ota_0`.

### 4. 2-Step Wildcard Provisioning Protocol Invariant
- The initial job payload from the verifier arrives with `key: ""` because key diversification requires the card's physical UID.
- The node must publish `writer/<device>/claim` with the UID, keep the tag activated in target slot 1 (never cycling the RF field mid-flow), and execute `provision_tag` only after the keyed claim reply arrives on `writer/<device>/job`.

### 5. No Line-Rate Loops (hard rule)

Any loop that can iterate faster than its poll/sleep interval is a line-rate
loop. They flood the UART ( burying real diagnostics under megabytes of one
line), flood the broker (EMQX logged `runq_overload` alarms from a firmware
CONNECT flood), starve sibling executor tasks (MQTT pings stop → broker kicks
with `keepalive_timeout`), and burn power. Every stability regression traced
so far shipped with one.

Rules:

- Every retry/connection loop gets a **hard sleep at the loop top** (`mqtt_runner`
  sleeps 1 s unconditionally before each cycle — `continue` paths cannot skip it).
- Every handshake gets a **timeout** (`session.connect` is capped at 10 s; a
  broker that accepts TCP but stalls CONNACK must not hold a zombie session).
- Liveness heartbeats (`[pump hb n]`, `[mqtt-cycle n]`) make a starved or
  hot-looping task visible in one capture instead of a bench day.
- The same applies to NFC waits: never spin-wait without the driver's
  timeout bound, and prefer the IRQ fast path below.

### 6. IRQ (GPIO4) — wire METER-VERIFIED 2026-10-22; arch-C implementation shipped behind `pn532-irq` (default OFF, pending bench E1-E4)

**Wire status:** the 2026-10-14 "untrusted" verdict was the mislanded slot of
the slid 8-pin harness, not the IRQ line. On 2026-10-22 the user ohmed the
GPIO4 harness wire out to the genuine PN532 IRQ pad at the bench. The wire may
stay connected in all builds — default builds never configure GPIO4.

**Electrical/protocol truth (UM0701-02):** P70_IRQ idles HIGH, asserts LOW
when a frame is ready — once for the ACK, once for the response (§6.2.5.2
Fig. 35, p. 48 — "the host controller … has no more need to read the status
byte"). SAMConfig's IRQ byte gates the driving; ours already sends 0x01
(Adafruit `01 14 01` parity; absent-parameter default is also 0x01, §7.2.10).
The PN532 releases IRQ on SPI DW/DR detection, so a stale LOW right after our
own reads is the EXPECTED spurious source — the 5f42f35 failure mode
(phantom LOW read as Ready) and the crate's send/ack race (WMT-GmbH/pn532#4)
are both absorbed by confirming every IRQ low with one STATREAD.

**Implementation (architecture C — `pn532-irq` feature, door only).** No
custom `Interface` (a blocking `wait_ready` inside the crate's sync loop
would park the embassy executor), no `process_async` (its `WaitReadyFuture`
self-wakes on Pending — a spin, WMT-GmbH/pn532#11). Instead nfc.rs drives the
crate's public fine-grained API (`send` / `receive_ack` / `receive_response`
/ `abort` + the public `interface` field) directly:

```
send(request)
→ wait_for_low() bounded by ack deadline (≤30 ms)
→ ONE STATREAD confirm via pn532.interface.wait_ready()
    Pending = stale/spurious low → re-wait (deadline-bounded; each
    STATREAD self-paces ~1 ms via the soft-SPI inter-transaction delay)
→ receive_ack()
→ wait_for_low() bounded by response deadline
→ STATREAD confirm (same loop)
→ receive_response()
on any ready-wait failure: pn532.abort() (host ACK forces resync)
```

Mechanics: `esp_hal::gpio::Input` on GPIO4, pull-up, level-triggered
`wait_for_low()` (stable API; catches an already-low pin — edge variants are
forbidden and would miss it; esp-hal binds the default GPIO interrupt handler
inside `esp_hal::init()`, so nothing else may register a GPIO handler — a
direct-bound handler breaks the async GPIO API entirely). The `Input` lives
in `nfc::IRQ_PIN` (embassy `Mutex<CriticalSectionRawMutex, Option<_>>`),
installed by `board::setup` before `init_pn532`. Every wait carries an
absolute deadline; budgets: ack 30 ms, SAMConfig/GetFirmwareVersion 500 ms,
InListPassiveTarget 600 ms (total — identical wall-clock bound to the
blocking path, so poll cadence/debounce/melody timing are unchanged),
InDataExchange 100 ms (task-spec'd; **watch E3** — the blocking path's 500 ms
was chosen for this module's high RF latencies; bump if Transport errors
appear), presence 150 ms, InRelease/RFConfiguration 100 ms.

Build:

```bash
KEYGATE_CHIP=esp32 ./run-in-rust-container.sh cargo build --release \
    --no-default-features --features chip-esp32,board-esp32-devkit-door,pn532-irq
```

(enabling it anywhere else fails a `compile_error!` guard in lib.rs). The
boot banner prints `door build: pn532 IRQ readiness (gpio4, meter-verified)`.

**Why this is not enabled by default — the E1-E4 bench gate** (all four must
pass on hardware before the feature is considered validated; the wire must be
IN for E1-E3):

- **E1 — boot/init:** wire IN, feature ON: `pn532 init ok` on the first or
  retry attempt, boot→bugle ≈5.5 s (AGENTS.md baseline), no `SAMConfig (irq)
  failed` storm. *This is the drill that answers whether this clone's P70_IRQ
  actually asserts on the 30 ms ack budget.*
- **E2 — idle behavior:** feature ON, 10+ min no tag: `[pump hb]` every 30 s,
  zero broker `keepalive_timeout`, poll heartbeat cadence unchanged vs the
  baseline capture. *Proves the level-wait parks the task instead of
  busy-spinning (the entire point of the feature).*
- **E3 — tap drills:** feature ON, 10 taps on a provisioned NTAG 424:
  detection latency ≤ baseline, SUN auth round-trip completes (GRANT),
  provisioning drill green; watch specifically for `in_data_exchange`
  Transport errors (the 100 ms budget vs the module's known-slow RF).
- **E4 — A/B regression:** feature OFF (default build) with the wire IN:
  behavior byte-identical to the pre-change baseline (the pin stays
  unconfigured; proves wire presence is harmless and the default path is
  untouched).

Until E1-E4 pass: readiness stays on the proven SPI STATREAD path in
default builds, exactly as before.

**History (5f42f35, reverted same day):** the first attempt sampled the pin
in `wait_ready` with the STATREAD poll as a *fallback for the stuck-HIGH
case* — a false LOW was indistinguishable from "response ready" because the
confirm step was missing. The arch-C design makes the STATREAD confirm
mandatory on every IRQ low, which is precisely the gap that killed 5f42f35.
