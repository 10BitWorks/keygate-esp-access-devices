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

#[macro_use]
mod diag;
mod auth_msg;
mod board;
mod cmd;
mod config;
mod nfc;
mod node;
mod ntag424;
mod ota;
mod ota_probation;
mod piezo;
mod platform;
mod provision;
mod provision_flow;
mod reader_supervisor;
mod relay;
mod status_led;
mod tag_debounce;

// Provide the application descriptor for the second-stage bootloader.
esp_bootloader_esp_idf::esp_app_desc!();

pub(crate) static BOOT_INFO: embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    Option<ota::BootInfo>,
> = embassy_sync::mutex::Mutex::new(None);

#[unsafe(no_mangle)]
unsafe extern "Rust" fn custom_halt() -> ! {
    esp_println::println!("[panic] resetting in ~2s");
    // ~2s bounded busy wait at 240 MHz — no alloc, no await (panic context)
    for i in 0..480_000_000u64 {
        core::hint::black_box(i);
    }
    esp_hal::system::software_reset();
}

/// Construct an RTC-WDT instance. `esp_hal::rtc_cntl::Rwdt` is a zero-sized
/// handle over the LP_WDT peripheral with no public constructor in esp-hal
/// 1.1.1; since it is a ZST, `MaybeUninit::uninit().assume_init()` is sound
/// (there are no bytes to initialize). The RTC WDT (RWDT) is the ROM-grade
/// watchdog and, unlike the TIMG1 MWDT, its config writes actually land on
/// classic ESP32 (see plan task 11).
fn rwdt_inst() -> esp_hal::rtc_cntl::Rwdt {
    // SAFETY: Rwdt is a zero-sized type; uninit() has no invalid bit patterns.
    unsafe { core::mem::MaybeUninit::uninit().assume_init() }
}

#[embassy_executor::task]
pub async fn wdt_feeder() -> ! {
    let mut wdt = rwdt_inst();
    #[cfg(feature = "bench-wedge")]
    let mut n: u8 = 0;
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(5)).await;
        #[cfg(feature = "bench-wedge")]
        if n < 2 {
            rwdt_diag("feeder-pre-feed");
        }
        wdt.feed();
        #[cfg(feature = "bench-wedge")]
        {
            if n < 2 {
                rwdt_diag("feeder-post-feed");
            }
            n = n.saturating_add(1);
        }
    }
}

/// Bench-only (bench-wedge) RTC-WDT code-path marker — task 11 confirmation.
/// (The classic-ESP32 LP_WDT peripheral is not exposed via `esp_hal::peripherals`,
/// so no raw register read here; the definitive proof that RWDT armed and fires
/// is the bench wedge drill itself: wedge -> RWDT reset.)
#[cfg(feature = "bench-wedge")]
pub(crate) fn rwdt_diag(tag: &str) {
    esp_println::println!("[rwdt] {}", tag);
}

#[embassy_executor::task]
async fn net_task(
    mut runner: embassy_net::Runner<'static, esp_radio::wifi::Interface<'static>>,
) -> ! {
    runner.run().await
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    // Boot stamp: which build is running. Mirrored into the diag ring so the
    // first MQTT connect publishes it to `access/<id>/log`.
    crate::blog!(
        "keygate {} fw git:{}",
        env!("CARGO_PKG_VERSION"),
        env!("KEYGATE_GIT_SHA")
    );

    // 1. Initialize heap allocator (72 KiB).
    esp_alloc::heap_allocator!(size: 72 * 1024);

    // 2. Initialize hardware.
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // 3. Early flash construction and probation check
    // Early boot flash access: steal a FLASH handle for the probation decision
    // tree ONLY (check + record/rollback) which must run before board::setup —
    // a new image that hangs inside setup must still count attempts. The stolen
    // wrapper is fully dropped before board::setup creates the one real
    // FlashStorage from the owned peripheral; single core, strictly sequential,
    // zero aliasing window.
    let mut early_flash =
        esp_storage::FlashStorage::new(unsafe { esp_hal::peripherals::FLASH::steal() });
    let boot = ota::boot_check(&mut early_flash).await;
    *BOOT_INFO.lock().await = Some(boot);

    if ota_probation::should_rollback(&boot.state) {
        esp_println::println!("[boot] probation failed — initiating rollback to previous slot");
        crate::blog!("probation failed — rolling back");
        if let Err(()) = ota::write_rollback(&mut early_flash, boot.max_seq, boot.booted_slot).await {
            esp_println::println!("[boot] rollback write failed — retrying next boot");
            crate::blog!("rollback write failed — retrying next boot");
        } else {
            esp_hal::system::software_reset();
        }
    } else if let ota_probation::MarkerState::Pending { attempts } = boot.state {
        esp_println::println!("[boot] probation pending — attempt {}/3", attempts + 1);
        if let Err(()) = ota::record_attempt(&mut early_flash).await {
            esp_println::println!("[boot] record attempt failed — deadline path will re-record");
            crate::blog!("probation record attempt failed");
        }
    }

    drop(early_flash);

    // 4. Arm the WDT before board::setup. Task-11 fix: use the RTC WDT (RWDT),
    // not the TIMG1 MWDT — on classic ESP32 the TIMG1 MWDT config writes do not
    // land (wdt_en stays 0, bench-proven), so the MWDT never arms nor fires.
    // RWDT is the ROM-grade watchdog in the RTC domain, independent of TIMG.
    let mut wdt = rwdt_inst();
    wdt.enable();
    wdt.set_timeout(
        esp_hal::rtc_cntl::RwdtStage::Stage0,
        esp_hal::time::Duration::from_secs(30),
    );
    drop(wdt);

    #[cfg(feature = "bench-wedge")]
    rwdt_diag("after-arm(pre-board-setup)");

    // 5. Initialize board and platform seams.
    let setup = board::setup(peripherals);
    ota::init_flash(setup.flash).await;

    #[cfg(feature = "bench-wedge")]
    crate::rwdt_diag("after-board-setup(post-esp_rtos-start)");

    // 6. Spawn the background tasks
    spawner.spawn(wdt_feeder().unwrap());
    spawner.spawn(status_led::status_led_task(setup.led_pin).unwrap());
    spawner.spawn(relay::relay_task(setup.relay_pin).unwrap());
    spawner.spawn(
        board::piezo_task(piezo::PIEZO_CHANNEL.receiver(), setup.piezo_tone).unwrap(),
    );
    spawner.spawn(net_task(setup.net_runner).unwrap());

    // Timer-driver sanity probe: a real 1 s sleep must measure ~1000 ms on
    // embassy's clock. A wildly different value means the time driver is not
    // backing Instant/Timer (cycle-count fallback) — every timeout in the
    // node would then fire instantly.
    {
        use embassy_time::{Duration, Instant, Timer};
        let t0 = Instant::now();
        Timer::after(Duration::from_millis(1000)).await;
        let dt_ms = (Instant::now() - t0).as_millis();
        esp_println::println!("[probe] Timer::after(1000ms) measured {} ms", dt_ms);
    }

    // 7. Transfer control to the node runtime loop.
    node::run(
        setup.pn532,
        setup.reader_reset,
        setup.stack,
        setup.wifi_controller,
    )
    .await
}
