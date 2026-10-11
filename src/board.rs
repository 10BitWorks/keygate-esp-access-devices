//! Board-specific pin mappings, peripheral initialization, and bus construction.
//!
//! Encapsulates board-level differences (e.g. XIAO ESP32-C6 vs classic ESP32 devkit door)
//! so the core orchestration in `main.rs` and node logic remain board-agnostic.

use esp_hal::{
    gpio::{Level, Output, OutputConfig},
    time::Rate,
};
#[cfg(feature = "board-xiao-c6")]
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_println::println;
use pn532::Pn532;

#[cfg(feature = "board-esp32-devkit-door")]
use embedded_hal::digital::OutputPin;
#[cfg(feature = "board-esp32-devkit-door")]
use embedded_hal::spi::{ErrorType, Operation, SpiBus, SpiDevice};
#[cfg(feature = "board-esp32-devkit-door")]
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

#[cfg(feature = "board-esp32-devkit-door")]
pub struct DoorSpiDevice<BUS, CS> {
    bus: BUS,
    cs: CS,
}

#[cfg(feature = "board-esp32-devkit-door")]
impl<BUS, CS> DoorSpiDevice<BUS, CS> {
    pub fn new(bus: BUS, cs: CS) -> Self {
        Self { bus, cs }
    }
}

#[cfg(feature = "board-esp32-devkit-door")]
impl<BUS: ErrorType, CS: OutputPin> ErrorType for DoorSpiDevice<BUS, CS> {
    type Error = BUS::Error;
}

#[cfg(feature = "board-esp32-devkit-door")]
impl<BUS: SpiBus, CS: OutputPin> SpiDevice for DoorSpiDevice<BUS, CS> {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        let _ = self.cs.set_low();
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
                Operation::DelayNs(_) => {}
            }
        }
        let _ = self.bus.flush();
        let _ = self.cs.set_high();
        res
    }
}

#[cfg(feature = "board-esp32-devkit-door")]
pub type Esp32SpiBus = esp_hal::spi::master::Spi<'static, esp_hal::Blocking>;
#[cfg(feature = "board-esp32-devkit-door")]
pub type DoorSpiDeviceImpl = DoorSpiDevice<Esp32SpiBus, esp_hal::gpio::Output<'static>>;
#[cfg(feature = "board-esp32-devkit-door")]
pub type DoorNfcIface = pn532::spi::SPIInterface<DoorSpiDeviceImpl>;

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
    println!("door build: pn532 SPI STATUS-poll (doc pins sck18 mosi23 miso19 cs5)");

    // 4. Spawn the status LED (GPIO2 onboard, active-low) and relay (GPIO13) tasks.
    //    GPIO13 chosen to avoid GPIO12/MTDI strapping pin issues.
    let led_pin = Output::new(peripherals.GPIO2, Level::High, OutputConfig::default());
    let relay_pin = Output::new(peripherals.GPIO13, Level::High, OutputConfig::default());

    // Hardware reset pin RSTO (GPIO21) wired to PN532 RSTPDN.
    // RSTPDN is active-low; hold high to keep PN532 out of reset.
    // Returned in Setup.reader_reset for remote lockup recovery in supervisor.
    let rsto = Output::new(peripherals.GPIO21, Level::High, OutputConfig::default());
    let reader_reset = Some(rsto);

    // 5 & 6. Initialize Wi-Fi and network stack via platform helpers.
    // Rng::new() is uniform across esp32 and c6.
    let rng = esp_hal::rng::Rng::new();
    let net_parts = platform::net(peripherals.WIFI, rng);

    // 7. Initialize SPI master and device for PN532.
    //    Documented door pinout (SPI2/VSPI): SCK=GPIO18, MOSI=GPIO23, MISO=GPIO19, CS=GPIO5,
    //    IRQ=GPIO4 (unused), RSTO=GPIO21, relay=GPIO13, LED=GPIO2.
    //    2026-10-11: prior devkit's die condemned after 5V excursion — SPI dead on both peripherals with fresh pins; this pinout targets the replacement board.
    //    Conservative 1 MHz clock, Mode 0.
    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_khz(1000))
            .with_mode(Mode::_0),
    )
    .unwrap()
    .with_sck(peripherals.GPIO18)
    .with_mosi(peripherals.GPIO23)
    .with_miso(peripherals.GPIO19);

    let cs = Output::new(peripherals.GPIO5, Level::High, OutputConfig::default());
    let spi_device = DoorSpiDevice::new(spi, cs);

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

