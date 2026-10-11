//! XIAO ESP32-C6 / ESP32 DevKit — Screenless NFC Reader Node
//!
//! Bare-metal Rust firmware for KeyGate access reader devices.
//!
//! Orchestrates heap initialization, board setup, asynchronous background tasks,
//! and passes execution to the runtime node loop in `node::run`.

#![no_std]
#![no_main]

extern crate alloc;

use embassy_executor::Spawner;
use esp_backtrace as _;
use esp_hal::clock::CpuClock;

mod auth_msg;
mod board;
mod cmd;
mod config;
mod nfc;
mod node;
mod ntag424;
mod platform;
mod reader_supervisor;
mod relay;
mod status_led;
mod tag_debounce;

// Provide the application descriptor for the second-stage bootloader.
esp_bootloader_esp_idf::esp_app_desc!();

#[embassy_executor::task]
async fn net_task(
    mut runner: embassy_net::Runner<'static, esp_radio::wifi::Interface<'static>>,
) -> ! {
    runner.run().await
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    // 1. Initialize heap allocator (72 KiB).
    esp_alloc::heap_allocator!(size: 72 * 1024);

    // 2. Initialize hardware.
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // 3. Initialize board and platform seams.
    let setup = board::setup(peripherals);

    // 4. Spawn the status LED and relay tasks.
    //    Each task takes ownership of its pin.
    spawner.spawn(status_led::status_led_task(setup.led_pin).unwrap());
    spawner.spawn(relay::relay_task(setup.relay_pin).unwrap());

    // 5. Spawn the Embassy network runner task.
    spawner.spawn(net_task(setup.net_runner).unwrap());

    // 6. Transfer control to the node runtime loop.
    node::run(
        setup.pn532,
        setup.reader_reset,
        setup.stack,
        setup.wifi_controller,
    )
    .await
}
