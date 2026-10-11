//! Board-specific pin mappings, peripheral initialization, and bus construction.
//!
//! Encapsulates board-level differences (e.g. XIAO ESP32-C6 vs classic ESP32 devkit door)
//! so the core orchestration in `main.rs` and node logic remain board-agnostic.

use esp_hal::gpio::{Level, Output, OutputConfig};
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
    platform,
};

/// Hardware and network resources initialized for a board.
pub struct Setup<I: pn532::Interface> {
    pub pn532: Option<Pn532<I, Pn532Delay, 300>>,
    pub reader_reset: Option<esp_hal::gpio::Output<'static>>,
    pub relay_pin: esp_hal::gpio::Output<'static>,
    pub led_pin: esp_hal::gpio::Output<'static>,
    pub wifi_controller: esp_radio::wifi::WifiController<'static>,
    pub stack: embassy_net::Stack<'static>,
    pub net_runner: embassy_net::Runner<'static, esp_radio::wifi::Interface<'static>>,
}

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
#[cfg(feature = "board-esp32-devkit-door")]
pub struct DoorSoftSpiDevice {
    sck: esp_hal::gpio::Output<'static>,
    mosi: esp_hal::gpio::Output<'static>,
    miso: esp_hal::gpio::Input<'static>,
    cs: esp_hal::gpio::Output<'static>,
    status_poll_count: u32,
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
        }
    }

    /// Wake the PN532 core from LowVbat/Standby mode via SPI.
    ///
    /// Per PN532 User Manual §7.1.1, waking the 80C51 core over SPI requires NSS/CS
    /// held LOW for ≥1 ms with no clocking (Adafruit_PN532::wakeup uses 2 ms).
    /// The `pn532` crate lacks this wakeup sequence, leaving the sleeping core unable
    /// to ACK commands while the SPI front-end answers STATUS polls with 0x00 forever.
    ///
    /// Timing math:
    /// Classic ESP32 CPU runs at 240 MHz (240 cycles/µs).
    /// 2,000 µs × 240 cycles/µs = 480,000 spin iterations (~1 cycle per spin loop iteration).
    pub fn wake(&mut self) {
        let _ = self.cs.set_low();
        for _ in 0..480_000 {
            core::hint::spin_loop();
        }
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
            // Half-period delay: ~1 µs at 240 MHz (240 spins).
            for _ in 0..240 {
                core::hint::spin_loop();
            }
            let _ = self.sck.set_high();
            // Half-period delay: ~1 µs at 240 MHz (240 spins).
            for _ in 0..240 {
                core::hint::spin_loop();
            }
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
            // Half-period delay: ~1 µs at 240 MHz (240 spins).
            for _ in 0..240 {
                core::hint::spin_loop();
            }
            let _ = self.sck.set_high();
            read_byte <<= 1;
            if self.miso.is_high() {
                read_byte |= 1;
            }
            // Half-period delay: ~1 µs at 240 MHz (240 spins).
            for _ in 0..240 {
                core::hint::spin_loop();
            }
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
        // CS settle delay: ~2 µs at 240 MHz (≈480 spin iterations).
        for _ in 0..480 {
            core::hint::spin_loop();
        }

        for op in operations {
            match op {
                Operation::Read(words) => {
                    // Clock out 0xFF read dummy byte per Adafruit convention;
                    // some PN532 revisions treat MOSI-low read dummies as false frame starts.
                    for byte in words.iter_mut() {
                        *byte = self.transfer_byte(0xFF);
                    }
                }
                Operation::Write(words) => {
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
                    let is_status_read = words.len() == 2 && words[0] == 0x40;
                    for byte in words.iter_mut() {
                        *byte = self.transfer_byte(*byte);
                    }
                    // Status-poll spy: prints raw STATUS bytes returned by PN532.
                    // 0x40 = as_lsb(0x02) = PN532_SPI_STATREAD under msb-spi pre-reversal.
                    // Spy semantics: 0xFF = module not driving MISO (mode/wiring/input-pin),
                    // 0x80 = ready (module talking), 0x00 = driving but not ready.
                    // Bound to first 8 polls only to avoid console flood.
                    if is_status_read && self.status_poll_count < 8 {
                        esp_println::println!(
                            "[softspi] status[{}] = 0x{:02X}",
                            self.status_poll_count,
                            words[1]
                        );
                        self.status_poll_count += 1;
                    }
                }
                Operation::DelayNs(ns) => {
                    // Approximate ~0.24 cycles/ns at 240 MHz (~ns / 4 spin iterations).
                    for _ in 0..(*ns / 4) {
                        core::hint::spin_loop();
                    }
                }
            }
        }

        // CS hold delay: ~2 µs at 240 MHz (≈480 spin iterations) before CS de-assertion.
        for _ in 0..480 {
            core::hint::spin_loop();
        }
        let _ = self.cs.set_high();
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
        // CS settle delay: ~10 µs at 240 MHz (240 cycles/µs * 10 µs = 2400 spins).
        for _ in 0..2400 {
            core::hint::spin_loop();
        }
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
                    // Approximate ~0.24 cycles/ns at 240 MHz (~ns / 4 spin iterations).
                    for _ in 0..(*ns / 4) {
                        core::hint::spin_loop();
                    }
                }
            }
        }
        let _ = self.bus.flush();
        // CS hold delay: ~10 µs at 240 MHz before CS de-assertion.
        for _ in 0..2400 {
            core::hint::spin_loop();
        }
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

#[cfg(feature = "board-xiao-c6")]
pub fn setup(peripherals: esp_hal::peripherals::Peripherals) -> Setup<XiaoNfcIface> {
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
        wifi_controller: net_parts.wifi_controller,
        stack: net_parts.stack,
        net_runner: net_parts.net_runner,
    }
}

#[cfg(feature = "board-esp32-devkit-door")]
pub fn setup(peripherals: esp_hal::peripherals::Peripherals) -> Setup<DoorNfcIface> {
    // 3. Initialize the RTOS scheduler (arch-uniform with xiao-c6).
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    platform::start_rtos(timg0.timer0, sw_interrupt.software_interrupt0);

    println!("ESP32 door node starting...");
    println!("door build: pn532 soft-SPI wake2ms (sck5 mosi22 miso18 cs17)");

    // 4. Spawn the status LED (GPIO2 onboard, active-low) and relay (GPIO13) tasks.
    //    GPIO13 chosen to avoid GPIO12/MTDI strapping pin issues.
    let led_pin = Output::new(peripherals.GPIO2, Level::High, OutputConfig::default());
    let relay_pin = Output::new(peripherals.GPIO13, Level::High, OutputConfig::default());

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

    // IRQ (GPIO4) intentionally unused: readiness is STATUS-polled over MISO.
    // IRQ-driven interface made init depend solely on the IRQ line and timed out at boot.
    let iface = pn532::spi::SPIInterface { spi: spi_device };

    // PN532 init is non-fatal: Wi-Fi/MQTT proceed regardless.
    let pn532 = match nfc::init_pn532(iface) {
        Ok(p) => {
            println!("PN532 initialized successfully!");
            Some(p)
        }
        Err(e) => {
            println!("PN532 init failed: {:?} — continuing without NFC", e);
            None
        }
    };

    Setup {
        pn532,
        reader_reset,
        relay_pin,
        led_pin,
        wifi_controller: net_parts.wifi_controller,
        stack: net_parts.stack,
        net_runner: net_parts.net_runner,
    }
}

