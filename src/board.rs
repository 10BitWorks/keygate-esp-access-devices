//! Board-specific pin mappings, peripheral initialization, and bus construction.
//!
//! Encapsulates board-level differences (e.g. XIAO ESP32-C6 vs classic ESP32 devkit door)
//! so the core orchestration in `main.rs` and node logic remain board-agnostic.

use esp_hal::gpio::{Level, Output, OutputConfig};
#[cfg(any(feature = "board-esp32-devkit-door", feature = "board-xiao-c6"))]
use esp_hal::ledc::{channel::ChannelIFace, timer::TimerIFace};
#[cfg(feature = "board-xiao-c6")]
use esp_hal::{
    i2c::master::{Config as I2cConfig, I2c},
    time::Rate,
};
use esp_println::println;
use pn532::Pn532;

#[cfg(feature = "board-esp32-devkit-door")]
use embedded_hal::digital::OutputPin;
#[cfg(feature = "board-esp32-devkit-door")]
use embedded_hal::spi::{ErrorType, Operation, SpiBus, SpiDevice};
#[cfg(feature = "board-esp32-devkit-door")]
use esp_hal::gpio::{Input, InputConfig, Pull};
#[cfg(feature = "board-esp32-devkit-door")]
#[allow(unused_imports)]
use esp_hal::{
    spi::master::{Config as SpiConfig, Spi},
    spi::Mode,
};

use crate::{
    nfc::{self, Pn532Delay},
    piezo,
    platform,
};

/// LEDC hardware-PWM tone driver: the peripheral emits the waveform from
/// its own clock — zero CPU during a tone, true parallelism with every
/// other task. Single-ended drive (bridge leg B idles low).
pub struct LedcTone {
    /// Private aliased handle for per-note frequency reconfiguration
    /// (esp-hal Timer handles alias the same registers by design).
    timer: esp_hal::ledc::timer::Timer<'static, esp_hal::ledc::LowSpeed>,
    ch: esp_hal::ledc::channel::Channel<'static, esp_hal::ledc::LowSpeed>,
}

/// Concrete piezo task for this board: the embassy task macro forbids
/// generics, so the LedcTone driver is bound here and the generic logic
/// lives in [`piezo::run`].
#[embassy_executor::task]
pub async fn piezo_task(rx: piezo::PiezoReceiver, tone: LedcTone) -> ! {
    piezo::run(rx, tone).await
}

impl piezo::ToneDriver for LedcTone {
    fn start(&mut self, freq_hz: u32) {
        self.timer
            .configure(esp_hal::ledc::timer::config::Config {
                duty: esp_hal::ledc::timer::config::Duty::Duty8Bit,
                clock_source: esp_hal::ledc::timer::LSClockSource::APBClk,
                frequency: esp_hal::time::Rate::from_hz(freq_hz),
            })
            .ok();
        self.ch.set_duty(50).ok();
    }

    fn stop(&mut self) {
        self.ch.set_duty(0).ok();
    }
}

/// Hardware and network resources initialized for a board.
pub struct Setup<I: pn532::Interface, T: piezo::ToneDriver> {
    pub pn532: Option<Pn532<I, Pn532Delay, 300>>,
    pub reader_reset: Option<esp_hal::gpio::Output<'static>>,
    pub relay_pin: esp_hal::gpio::Output<'static>,
    pub led_pin: esp_hal::gpio::Output<'static>,
    pub piezo_tone: T,
    pub flash: esp_storage::FlashStorage<'static>,
    pub wdt: esp_hal::timer::timg::Wdt<esp_hal::peripherals::TIMG1<'static>>,
    // Consumed by the node feedback hooks (task T7), which receive this sender
    // through `node::run`. Until those hooks land the field is intentionally
    // unread; silence the dead-code lint the same way `board.rs` does elsewhere.
    #[allow(dead_code)]
    pub piezo_tx: piezo::PiezoSender,
    pub wifi_controller: esp_radio::wifi::WifiController<'static>,
    pub stack: embassy_net::Stack<'static>,
    pub net_runner: embassy_net::Runner<'static, esp_radio::wifi::Interface<'static>>,
}

/// GPIO legs (A, B) driving the passive piezo disc in bridge mode.
///
/// The disc is polarity-free, so leg order is arbitrary. Door unit uses
/// `(GPIO32, GPIO33)` (user-confirmed free); XIAO-C6 uses `(GPIO9, GPIO10)`.
#[cfg(feature = "board-esp32-devkit-door")]
pub const PIEZO_PINS: (u8, u8) = (32, 33);
#[cfg(feature = "board-xiao-c6")]
pub const PIEZO_PINS: (u8, u8) = (9, 10);

#[cfg(feature = "board-xiao-c6")]
pub type I2cBus = esp_hal::i2c::master::I2c<'static, esp_hal::Blocking>;
#[cfg(feature = "board-xiao-c6")]
pub type XiaoNfcIface = pn532::i2c::I2CInterface<I2cBus>;

/// Bit-banged software SPI device for the door PN532.
///
/// Bypasses the esp-hal hardware SPI peripheral by directly driving SCK, MOSI, and CS
/// as output GPIOs and sampling MISO as an input GPIO.
///
/// Bit-bangs SPI Mode 0 (CPOL=0, CPHA=0):
/// - SCK idles low.
/// - MOSI is driven while SCK is low, then SCK is pulsed high.
/// - MISO is sampled while SCK is high.
/// - Inter-bit half-period delay is ~1 µs (≈240 spins at 240 MHz CPU, ~2 µs full period).
///   With function calls and loop overhead, effective clock is ~100 kHz.
///   Math: a 35-byte frame is 280 bits ≈ 3 ms transmission time, well within the 200 ms poll cadence.
///
/// CRITICAL bit-order note:
/// The PN532 communicates LSB-first over the SPI wire. However, the `pn532` crate's `msb-spi`
/// feature reverses frame bytes BEFORE passing them to `write()`, and pre-reverses the
/// STATREAD/DATAWRITE/DATAREAD header constants (e.g. PN532_SPI_READY). Therefore, this soft
/// device must clock each byte MSB-first, exactly like a hardware MSB-first SPI controller.
/// Do NOT add any extra bit reversal here. In `wait_ready`, `buf[1] == PN532_SPI_READY` expects
/// the status byte to arrive already-reversed by MSB-first clocking of the PN532's LSB-first
/// wire stream, matching the pre-reversed constant.
/// Real-time busy-wait. Plain `core::hint::spin_loop()` loops are side-effect-free
/// and LLVM collapses them entirely in release builds — every ms-scale delay in
/// this driver silently vanished (STATUS polls ran at ~121 kHz instead of ~1 kHz,
/// starving the PN532's 80C51 core during RF commands). `black_box` per iteration
/// keeps the loop materialized: ~2-4 cycles per iteration at 240 MHz.
#[cfg(feature = "board-esp32-devkit-door")]
#[inline(never)]
fn spin_delay(iterations: u32) {
    for i in 0..iterations {
        core::hint::black_box(i);
    }
}

// Spy counter fields are only exercised under the `nfc-spy` feature; silence dead-code
// lints for production builds. See docs/PN532-SPI-NOTES.md for spy output semantics.
#[cfg(feature = "board-esp32-devkit-door")]
#[cfg_attr(not(feature = "nfc-spy"), allow(dead_code))]
pub struct DoorSoftSpiDevice {
    sck: esp_hal::gpio::Output<'static>,
    mosi: esp_hal::gpio::Output<'static>,
    miso: esp_hal::gpio::Input<'static>,
    cs: esp_hal::gpio::Output<'static>,
    status_poll_count: u32,
    status_print_count: u32,
    last_status: Option<u8>,
    write_count: u32,
    read_dump_count: u32,
    frame_read_pending: bool,
}

#[cfg(feature = "board-esp32-devkit-door")]
impl DoorSoftSpiDevice {
    pub fn new(
        sck: esp_hal::gpio::Output<'static>,
        mosi: esp_hal::gpio::Output<'static>,
        miso: esp_hal::gpio::Input<'static>,
        cs: esp_hal::gpio::Output<'static>,
    ) -> Self {
        Self {
            sck,
            mosi,
            miso,
            cs,
            status_poll_count: 0,
            status_print_count: 0,
            last_status: None,
            write_count: 0,
            read_dump_count: 0,
            frame_read_pending: false,
        }
    }

    /// Wake the PN532 core from LowVbat/Standby mode via SPI.
    ///
    /// Per PN532 User Manual §7.1.1, waking the 80C51 core over SPI requires NSS/CS
    /// held LOW for ≥1 ms with no clocking (Adafruit_PN532::wakeup uses 2 ms).
    /// The `pn532` crate lacks this wakeup sequence, leaving the sleeping core unable
    /// to ACK commands while the SPI front-end answers STATUS polls with 0x00 forever.
    ///
    /// Timing: spin_delay materializes at ~2-4 cycles/iteration at 240 MHz;
    /// 150,000 iterations ≈ 1.5-2 ms of real CS-low time.
    pub fn wake(&mut self) {
        let _ = self.cs.set_low();
        spin_delay(150_000);
        let _ = self.cs.set_high();
    }

    #[inline(always)]
    fn write_byte(&mut self, mut byte: u8) {
        for _ in 0..8 {
            if (byte & 0x80) != 0 {
                let _ = self.mosi.set_high();
            } else {
                let _ = self.mosi.set_low();
            }
            byte <<= 1;
            // Half-period delay: ~1 µs (spin_delay — plain spin_loop was
            // optimized out entirely in release builds).
            spin_delay(100);
            let _ = self.sck.set_high();
            // Half-period delay: ~1 µs (spin_delay — plain spin_loop was
            // optimized out entirely in release builds).
            spin_delay(100);
            let _ = self.sck.set_low();
        }
    }

    #[inline(always)]
    fn transfer_byte(&mut self, mut write_byte: u8) -> u8 {
        let mut read_byte = 0u8;
        for _ in 0..8 {
            if (write_byte & 0x80) != 0 {
                let _ = self.mosi.set_high();
            } else {
                let _ = self.mosi.set_low();
            }
            write_byte <<= 1;
            // Half-period delay: ~1 µs (spin_delay — plain spin_loop was
            // optimized out entirely in release builds).
            spin_delay(100);
            let _ = self.sck.set_high();
            read_byte <<= 1;
            if self.miso.is_high() {
                read_byte |= 1;
            }
            // Half-period delay: ~1 µs (spin_delay — plain spin_loop was
            // optimized out entirely in release builds).
            spin_delay(100);
            let _ = self.sck.set_low();
        }
        read_byte
    }
}

#[cfg(feature = "board-esp32-devkit-door")]
impl ErrorType for DoorSoftSpiDevice {
    type Error = core::convert::Infallible;
}

#[cfg(feature = "board-esp32-devkit-door")]
impl SpiDevice for DoorSoftSpiDevice {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        let _ = self.cs.set_low();
        spin_delay(200); // CS settle ~2 µs before first clock edge

        for op in operations {
            match op {
                Operation::Read(words) => {
                    // Clock out 0xFF read dummy byte per Adafruit convention;
                    // some PN532 revisions treat MOSI-low read dummies as false frame starts.
                    for byte in words.iter_mut() {
                        *byte = self.transfer_byte(0xFF);
                    }
                    // Frame spy: dump the ACK/response frames fetched via DATAREAD
                    // (crate sends Write([0xC0]) immediately before the Read op).
                    // 80 dumps cover init exchanges plus a full tag-tap sequence.
                    #[cfg(feature = "nfc-spy")]
                    if self.frame_read_pending && self.read_dump_count < 80 {
                        self.frame_read_pending = false;
                        esp_println::print!("[softspi] frame rd ({} B) wire: ", words.len());
                        for b in words.iter().take(40) {
                            esp_println::print!("{:02X} ", b);
                        }
                        esp_println::println!("");
                        esp_println::print!("[softspi] frame logical: ");
                        for b in words.iter().take(40) {
                            esp_println::print!("{:02X} ", b.reverse_bits());
                        }
                        esp_println::println!("");
                        self.read_dump_count += 1;
                    }
                }
                Operation::Write(words) => {
                    #[cfg(feature = "nfc-spy")]
                    if self.write_count < 400 {
                        esp_println::print!("[softspi] write[{}]: ", words.len());
                        for b in words.iter().take(32) {
                            esp_println::print!("{:02X} ", b);
                        }
                        esp_println::println!("");
                        esp_println::print!("[softspi] write[{}] unreversed: ", words.len());
                        for b in words.iter().take(32) {
                            esp_println::print!("{:02X} ", b.reverse_bits());
                        }
                        esp_println::println!("");
                        self.write_count += 1;
                    }
                    // DATAREAD selector (wire 0xC0) marks the next Read op as a frame fetch.
                    #[cfg(feature = "nfc-spy")]
                    if words.len() == 1 && words[0] == 0xC0 {
                        self.frame_read_pending = true;
                    }
                    for &byte in words.iter() {
                        self.write_byte(byte);
                    }
                }
                Operation::Transfer(read, write) => {
                    let len = read.len().min(write.len());
                    for i in 0..len {
                        read[i] = self.transfer_byte(write[i]);
                    }
                    if write.len() > len {
                        for &b in &write[len..] {
                            self.write_byte(b);
                        }
                    } else if read.len() > len {
                        for b in &mut read[len..] {
                            *b = self.transfer_byte(0x00);
                        }
                    }
                }
                Operation::TransferInPlace(words) => {
                    for byte in words.iter_mut() {
                        *byte = self.transfer_byte(*byte);
                    }
                    // Status spy: logs every STATUS VALUE CHANGE (bounded), not every poll.
                    // Reveals the ready-timeline during long RF commands — e.g. whether
                    // the module ever flips to ready (0x80) inside InListPassiveTarget's
                    // window, flips back, or asserts garbage (BadAck hunting).
                    // 0x40 = as_lsb(0x02) = PN532_SPI_STATREAD under msb-spi pre-reversal.
                    // Semantics: 0xFF = MISO not driven (mode/wiring), 0x80 = ready,
                    // 0x00 = driving but not ready. See docs/PN532-SPI-NOTES.md.
                    #[cfg(feature = "nfc-spy")]
                    {
                        let is_status_read = words.len() == 2 && words[0] == 0x40;
                        if is_status_read {
                            if self.status_print_count < 400
                                && self.last_status != Some(words[1])
                            {
                                esp_println::println!(
                                    "[softspi] status poll #{} -> 0x{:02X}",
                                    self.status_poll_count,
                                    words[1]
                                );
                                self.last_status = Some(words[1]);
                                self.status_print_count += 1;
                            }
                            self.status_poll_count += 1;
                        }
                    }
                }
                Operation::DelayNs(ns) => {
                    // ~10-16 ns per spin_delay iteration at 240 MHz.
                    spin_delay(*ns / 12);
                }
            }
        }

        spin_delay(200); // CS hold ~2 µs before CS de-assertion
        let _ = self.cs.set_high();

        // Inter-transaction CS-high idle delay: ~1 ms. Gives the PN532's 80C51 core
        // quiet bus time to process commands (Adafruit uses delay(1) post-write and
        // delay(10) between polls). THE critical pacing: without a real delay here,
        // STATUS polling hammers the bus at ~121 kHz and RF commands starve.
        spin_delay(75_000); // ~0.75-1.2 ms

        Ok(())
    }
}

#[cfg(feature = "board-esp32-devkit-door")]
#[allow(dead_code)]
pub struct DoorSpiDevice<BUS, CS> {
    bus: BUS,
    cs: CS,
}

#[cfg(feature = "board-esp32-devkit-door")]
#[allow(dead_code)]
impl<BUS, CS> DoorSpiDevice<BUS, CS> {
    pub fn new(bus: BUS, cs: CS) -> Self {
        Self { bus, cs }
    }
}

#[cfg(feature = "board-esp32-devkit-door")]
#[allow(dead_code)]
impl<BUS: ErrorType, CS: OutputPin> ErrorType for DoorSpiDevice<BUS, CS> {
    type Error = BUS::Error;
}

// PN532 requires a CS-to-SCK settle delay after asserting CS low before the first
// clock edge, as well as hold time before releasing CS. Without this delay, the PN532
// drops the frame's first byte or responds with garbage/TimeoutAck (WMT-GmbH/pn532
// issue #21; ESP-IDF pn532-spi-idf documentation).
// Classic ESP32 CPU runs at 240 MHz (~240 cycles/µs). ~2400 spin iterations yields ~10 µs.
#[cfg(feature = "board-esp32-devkit-door")]
#[allow(dead_code)]
impl<BUS: SpiBus, CS: OutputPin> SpiDevice for DoorSpiDevice<BUS, CS> {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        let _ = self.cs.set_low();
        spin_delay(1000); // CS settle ~10 µs
        let mut res = Ok(());
        for op in operations {
            match op {
                Operation::Read(words) => {
                    if let Err(e) = self.bus.read(words) {
                        res = Err(e);
                        break;
                    }
                }
                Operation::Write(words) => {
                    if let Err(e) = self.bus.write(words) {
                        res = Err(e);
                        break;
                    }
                }
                Operation::Transfer(read, write) => {
                    if let Err(e) = self.bus.transfer(read, write) {
                        res = Err(e);
                        break;
                    }
                }
                Operation::TransferInPlace(words) => {
                    if let Err(e) = self.bus.transfer_in_place(words) {
                        res = Err(e);
                        break;
                    }
                }
                Operation::DelayNs(ns) => {
                    // ~10-16 ns per spin_delay iteration at 240 MHz.
                    spin_delay(*ns / 12);
                }
            }
        }
        let _ = self.bus.flush();
        spin_delay(1000); // CS hold ~10 µs
        let _ = self.cs.set_high();
        res
    }
}

#[cfg(feature = "board-esp32-devkit-door")]
#[allow(dead_code)]
pub type Esp32SpiBus = esp_hal::spi::master::Spi<'static, esp_hal::Blocking>;
#[cfg(feature = "board-esp32-devkit-door")]
#[allow(dead_code)]
pub type DoorSpiDeviceImpl = DoorSpiDevice<Esp32SpiBus, esp_hal::gpio::Output<'static>>;
#[cfg(feature = "board-esp32-devkit-door")]
pub type DoorNfcIface = pn532::spi::SPIInterface<DoorSoftSpiDevice>;

/// HISTORY — twice-poisoned wrapper experiments, do not reintroduce:
/// Any `Instant::now()` call inside `write()` before the SPI transaction
/// kills PN532 init on this target (ESP32 classic + esp-rtos): frames go
/// out but the module never asserts ready (status=0x00 all window). BOTH
/// clock sources falsified at the bench with the GPIO4 wire OUT:
/// `esp_hal::time::Instant` (76e9c78–0e49810 builds) AND
/// `embassy_time::Instant` (2026-10-14 23:00 build — SAMConfig TimeoutAck
/// ×3). Plain `SPIInterface` (this alias) is the only config that inits.
/// If per-command latency is ever needed again, measure it in `wait_ready`
/// only — never touch a clock in `write()`.
///
/// GPIO4 ("IRQ" harness slot) stays physically disconnected AND
/// unconfigured: live A/B (user at bench) showed wire-in kills the reader
/// on builds that never touch the pin — mislanded harness line. Meter it
/// before ever trusting it.

#[cfg(feature = "board-xiao-c6")]
pub fn setup(
    peripherals: esp_hal::peripherals::Peripherals,
) -> Setup<XiaoNfcIface, LedcTone> {
    // 3. Initialize the RTOS scheduler.
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    platform::start_rtos(timg0.timer0, sw_interrupt.software_interrupt0);

    println!("XIAO-C6 NFC node starting...");

    // 4. Spawn the status LED (GPIO15, active-low) and relay (GPIO1) tasks.
    //    Each task takes ownership of its pin.
    let led_pin = Output::new(peripherals.GPIO15, Level::High, OutputConfig::default());
    let relay_pin = Output::new(peripherals.GPIO1, Level::High, OutputConfig::default());

    // Passive piezo disc on GPIO9, driven by LEDC hardware PWM (zero CPU
    // during tones). GPIO10 (old bridge leg B) idles low, forgotten so the
    // pad keeps its level for the life of the process.
    let mut ledc = esp_hal::ledc::Ledc::new(peripherals.LEDC);
    ledc.set_global_slow_clock(esp_hal::ledc::LSGlobalClkSource::APBClk);
    // The channel stores one shared timer reference at configure time
    // (frozen); a second aliased handle lives in LedcTone for per-note
    // frequency changes — esp-hal Timer handles alias the same registers.
    static LEDC_TIMER: static_cell::StaticCell<esp_hal::ledc::timer::Timer<'static, esp_hal::ledc::LowSpeed>> =
        static_cell::StaticCell::new();
    let t_frozen: &'static mut esp_hal::ledc::timer::Timer<'static, esp_hal::ledc::LowSpeed> =
        LEDC_TIMER.init(ledc.timer::<esp_hal::ledc::LowSpeed>(esp_hal::ledc::timer::Number::Timer0));
    t_frozen
        .configure(esp_hal::ledc::timer::config::Config {
            duty: esp_hal::ledc::timer::config::Duty::Duty8Bit,
            clock_source: esp_hal::ledc::timer::LSClockSource::APBClk,
            frequency: esp_hal::time::Rate::from_hz(1047),
        })
        .unwrap();
    let timer_for_freq = ledc.timer::<esp_hal::ledc::LowSpeed>(esp_hal::ledc::timer::Number::Timer0);
    let mut ch0 = ledc.channel::<esp_hal::ledc::LowSpeed>(
        esp_hal::ledc::channel::Number::Channel0,
        peripherals.GPIO9,
    );
    ch0.configure(esp_hal::ledc::channel::config::Config {
        timer: &*t_frozen,
        duty_pct: 0,
        drive_mode: esp_hal::gpio::DriveMode::PushPull,
    })
    .unwrap();
    let piezo_tone = LedcTone {
        timer: timer_for_freq,
        ch: ch0,
    };
    let flash = esp_storage::FlashStorage::new(peripherals.FLASH);
    // Task watchdog on TIMG1: any wedged task (flash op, driver bug)
    // reboots the node within 30s — the old build keeps guarding.
    let mut wdt = esp_hal::timer::timg::Wdt::<esp_hal::peripherals::TIMG1<'static>>::new();
    wdt.enable();
    wdt.set_timeout(
        esp_hal::timer::timg::MwdtStage::Stage0,
        esp_hal::time::Duration::from_secs(30),
    );
    core::mem::forget(Output::new(
        peripherals.GPIO10,
        Level::Low,
        OutputConfig::default(),
    ));
    // 5 & 6. Initialize Wi-Fi and network stack via platform helpers.
    let rng = esp_hal::rng::Rng::new();
    let net_parts = platform::net(peripherals.WIFI, rng);

    // 7. Initialize I2C for the PN532.
    //    XIAO ESP32-C6 pinout: D4 = GPIO2 (SDA), D5 = GPIO3 (SCL).
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(100)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO2)
    .with_scl(peripherals.GPIO3);

    println!("I2C initialized on GPIO2 (SDA) / GPIO3 (SCL)");

    // PN532 init is non-fatal: Wi-Fi/MQTT proceed regardless.
    let pn532 = match nfc::init_pn532(pn532::i2c::I2CInterface { i2c }) {
        Ok(p) => {
            println!("PN532 initialized successfully!");
            Some(p)
        }
        Err(e) => {
            println!("PN532 init failed: {:?} — continuing without NFC", e);
            None
        }
    };

    // XIAO-C6 has no dedicated hardware reset line (RSTO) wired to the PN532.
    // Lockup recovery on this board relies on soft re-initialization.
    let reader_reset = None;

    Setup {
        pn532,
        reader_reset,
        relay_pin,
        led_pin,
        piezo_tone,
        flash,
        wdt,
        piezo_tx: piezo::PIEZO_CHANNEL.sender(),
        wifi_controller: net_parts.wifi_controller,
        stack: net_parts.stack,
        net_runner: net_parts.net_runner,
    }
}

#[cfg(feature = "board-esp32-devkit-door")]
pub fn setup(
    peripherals: esp_hal::peripherals::Peripherals,
) -> Setup<DoorNfcIface, LedcTone> {
    // 3. Initialize the RTOS scheduler (arch-uniform with xiao-c6).
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    platform::start_rtos(timg0.timer0, sw_interrupt.software_interrupt0);

    println!("ESP32 door node starting...");
    println!("door build: provision+piezo");
    #[cfg(feature = "nfc-spy")]
    println!("door build: pn532 soft-SPI SPY (sck5 mosi22 miso18 cs17)");
    #[cfg(not(feature = "nfc-spy"))]
    println!("door build: pn532 soft-SPI (sck5 mosi22 miso18 cs17)");

    // 4. Spawn the status LED (GPIO2 onboard, active-low) and relay (GPIO13) tasks.
    //    GPIO13 chosen to avoid GPIO12/MTDI strapping pin issues.
    let led_pin = Output::new(peripherals.GPIO2, Level::High, OutputConfig::default());
    let relay_pin = Output::new(peripherals.GPIO13, Level::High, OutputConfig::default());

    // Passive piezo disc on GPIO32, driven by LEDC hardware PWM (zero CPU
    // during tones). GPIO33 (old bridge leg B) idles low, forgotten so the
    // pad keeps its level for the life of the process.
    let mut ledc = esp_hal::ledc::Ledc::new(peripherals.LEDC);
    ledc.set_global_slow_clock(esp_hal::ledc::LSGlobalClkSource::APBClk);
    // The channel stores one shared timer reference at configure time
    // (frozen); a second aliased handle lives in LedcTone for per-note
    // frequency changes — esp-hal Timer handles alias the same registers.
    static LEDC_TIMER: static_cell::StaticCell<esp_hal::ledc::timer::Timer<'static, esp_hal::ledc::LowSpeed>> =
        static_cell::StaticCell::new();
    let t_frozen: &'static mut esp_hal::ledc::timer::Timer<'static, esp_hal::ledc::LowSpeed> =
        LEDC_TIMER.init(ledc.timer::<esp_hal::ledc::LowSpeed>(esp_hal::ledc::timer::Number::Timer0));
    t_frozen
        .configure(esp_hal::ledc::timer::config::Config {
            duty: esp_hal::ledc::timer::config::Duty::Duty8Bit,
            clock_source: esp_hal::ledc::timer::LSClockSource::APBClk,
            frequency: esp_hal::time::Rate::from_hz(1047),
        })
        .unwrap();
    let timer_for_freq = ledc.timer::<esp_hal::ledc::LowSpeed>(esp_hal::ledc::timer::Number::Timer0);
    let mut ch0 = ledc.channel::<esp_hal::ledc::LowSpeed>(
        esp_hal::ledc::channel::Number::Channel0,
        peripherals.GPIO32,
    );
    ch0.configure(esp_hal::ledc::channel::config::Config {
        timer: &*t_frozen,
        duty_pct: 0,
        drive_mode: esp_hal::gpio::DriveMode::PushPull,
    })
    .unwrap();
    let piezo_tone = LedcTone {
        timer: timer_for_freq,
        ch: ch0,
    };
    let flash = esp_storage::FlashStorage::new(peripherals.FLASH);
    // Task watchdog on TIMG1: any wedged task (flash op, driver bug)
    // reboots the node within 30s — the old build keeps guarding.
    let mut wdt = esp_hal::timer::timg::Wdt::<esp_hal::peripherals::TIMG1<'static>>::new();
    wdt.enable();
    wdt.set_timeout(
        esp_hal::timer::timg::MwdtStage::Stage0,
        esp_hal::time::Duration::from_secs(30),
    );
    core::mem::forget(Output::new(
        peripherals.GPIO33,
        Level::Low,
        OutputConfig::default(),
    ));

    // Hardware reset pin RSTO on GPIO19 (repurposed from MISO).
    // The 8-pin harness was slid one slot up the right column; GPIO19's INPUT buffer is the
    // 5V-excursion suspect, but driving it as an RSTO output is safe.
    // RSTPDN is active-low; hold high to keep PN532 out of reset.
    // User may leave it unwired on bench — driving high is harmless.
    // Returned in Setup.reader_reset for remote lockup recovery in supervisor.
    let rsto = Output::new(peripherals.GPIO19, Level::High, OutputConfig::default());
    let reader_reset = Some(rsto);

    // 5 & 6. Initialize Wi-Fi and network stack via platform helpers.
    // Rng::new() is uniform across esp32 and c6.
    let rng = esp_hal::rng::Rng::new();
    let net_parts = platform::net(peripherals.WIFI, rng);

    // 7. Initialize bit-banged software SPI device for PN532.
    //    Harness slid one slot up the right column:
    //    SCK=GPIO5, MOSI=GPIO22, MISO=GPIO18, CS=GPIO17, RSTO=GPIO19.
    //    GPIO18 input path is virgin (was SCK-output all session).
    //    GPIO19's input buffer is the 5V-excursion suspect (using it as RSTO output is safe).
    //    Bit-banged Mode 0 over plain GPIOs with ~100 kHz effective clock.
    let sck = Output::new(peripherals.GPIO5, Level::Low, OutputConfig::default());
    let mosi = Output::new(peripherals.GPIO22, Level::Low, OutputConfig::default());
    let miso = Input::new(
        peripherals.GPIO18,
        InputConfig::default().with_pull(Pull::Up),
    );
    let cs = Output::new(peripherals.GPIO17, Level::High, OutputConfig::default());
    let mut spi_device = DoorSoftSpiDevice::new(sck, mosi, miso, cs);

    // Mirrors Adafruit begin() = reset -> delay -> wakeup -> SAMConfig.
    // Wake the PN532 core from low-power standby before wrapping spi_device in SPIInterface.
    spi_device.wake();

    // GPIO4 ("IRQ" harness slot) intentionally left UNCONFIGURED and the
    // wire stays physically disconnected — see the DoorNfcIface history note.
    let iface = pn532::spi::SPIInterface { spi: spi_device };

    // PN532 init is non-fatal: Wi-Fi/MQTT proceed regardless.
    let pn532 = match nfc::init_pn532(iface) {
        Ok(p) => {
            println!("PN532 initialized successfully!");
            crate::blog!("pn532 init ok");
            Some(p)
        }
        Err(e) => {
            println!("PN532 init failed: {:?} — continuing without NFC", e);
            crate::blog!("pn532 init failed");
            None
        }
    };

    Setup {
        pn532,
        reader_reset,
        relay_pin,
        led_pin,
        piezo_tone,
        flash,
        wdt,
        piezo_tx: piezo::PIEZO_CHANNEL.sender(),
        wifi_controller: net_parts.wifi_controller,
        stack: net_parts.stack,
        net_runner: net_parts.net_runner,
    }
}

