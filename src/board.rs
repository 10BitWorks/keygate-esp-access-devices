//! Board-specific pin mappings, peripheral initialization, and bus construction.
//!
//! Encapsulates board-level differences (e.g. XIAO ESP32-C6 vs classic ESP32 devkit door)
//! so the core orchestration in `main.rs` and node logic remain board-agnostic.

use esp_hal::{
    gpio::{Level, Output, OutputConfig},
    i2c::master::{Config as I2cConfig, I2c},
    time::Rate,
};
use esp_println::println;
use pn532::Pn532;

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

pub type I2cBus = esp_hal::i2c::master::I2c<'static, esp_hal::Blocking>;
pub type XiaoNfcIface = pn532::i2c::I2CInterface<I2cBus>;

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
