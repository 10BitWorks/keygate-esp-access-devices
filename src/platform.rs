//! Architecture-uniform platform initializers.
//!
//! Helpers in this module initialize core runtime components (RTOS scheduler,
//! Wi-Fi controller, and Embassy network stack) that share identical interfaces
//! across supported ESP chips.

use esp_println::println;
use static_cell::StaticCell;

use crate::config;

/// Parts produced by Wi-Fi and network stack initialization.
pub struct NetParts {
    pub wifi_controller: esp_radio::wifi::WifiController<'static>,
    pub stack: embassy_net::Stack<'static>,
    pub net_runner: embassy_net::Runner<'static, esp_radio::wifi::Interface<'static>>,
}

/// Initialize the RTOS scheduler.
pub fn start_rtos(
    timer0: impl esp_rtos::TimerSource,
    sw_int0: esp_hal::interrupt::software::SoftwareInterrupt<'static, 0>,
) {
    esp_rtos::start(timer0, sw_int0);
}

/// Initialize Wi-Fi controller and the Embassy network stack.
pub fn net(wifi: esp_hal::peripherals::WIFI<'static>, rng: esp_hal::rng::Rng) -> NetParts {
    println!("Configuring WiFi...");
    let (mut wifi_controller, interfaces) = esp_radio::wifi::new(
        wifi,
        esp_radio::wifi::ControllerConfig::default(),
    )
    .unwrap();

    let station_config = esp_radio::wifi::Config::Station(
        esp_radio::wifi::sta::StationConfig::default()
            .with_ssid(config::WIFI_SSID)
            .with_password(config::WIFI_PASS.into()),
    );
    wifi_controller.set_config(&station_config).unwrap();

    let seed = ((rng.random() as u64) << 32) | (rng.random() as u64);

    static RESOURCES: StaticCell<embassy_net::StackResources<5>> = StaticCell::new();
    let resources = RESOURCES.init(embassy_net::StackResources::<5>::new());

    let (stack, net_runner) = embassy_net::new(
        interfaces.station,
        embassy_net::Config::dhcpv4(Default::default()),
        resources,
        seed,
    );

    NetParts {
        wifi_controller,
        stack,
        net_runner,
    }
}
