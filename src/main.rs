//! XIAO ESP32-C6 — Screenless NFC Reader Node
//!
//! Bare-metal Rust firmware for Seeed Studio XIAO ESP32-C6 boards.
//!
//! Each node reads NTAG 424 DNA tags via a PN532 (I2C), extracts the SUN
//! (Secure Unique NFC) mirror parameters from the NDEF URI, publishes an
//! authentication request to `access/<device_id>/auth`, and actuates a door
//! strike relay when the verifier grants access on `access/<device_id>/cmd`.

#![no_std]
#![no_main]

extern crate alloc;

use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Level, Output, OutputConfig},
    i2c::master::{Config as I2cConfig, I2c},
    time::Rate,
};
use esp_println::println;

use core::fmt::Write;
use embassy_executor::Spawner;
use embassy_net::{tcp::TcpSocket, StackResources};
use embassy_time::{Duration, Instant, Timer};
use minimq::{
    Buffers, ConfigBuilder, ConnectEvent, Publication, Session, TopicFilter, Will,
};
use static_cell::StaticCell;

mod auth_msg;
mod cmd;
mod config;
mod nfc;
mod ntag424;
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

    // 2. Initialize peripherals.
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // 3. Initialize the RTOS scheduler.
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_interrupt.software_interrupt0);

    println!("XIAO-C6 NFC node starting...");

    // 4. Spawn the status LED (GPIO15, active-low) and relay (GPIO1) tasks.
    //    Each task takes ownership of its pin.
    let led = Output::new(peripherals.GPIO15, Level::High, OutputConfig::default());
    let relay_pin = Output::new(peripherals.GPIO1, Level::High, OutputConfig::default());
    spawner.spawn(status_led::status_led_task(led).unwrap());
    spawner.spawn(relay::relay_task(relay_pin).unwrap());

    // 5. Initialize Wi-Fi.
    println!("Configuring WiFi...");
    let (mut wifi_controller, interfaces) = esp_radio::wifi::new(
        peripherals.WIFI,
        esp_radio::wifi::ControllerConfig::default(),
    )
    .unwrap();

    let station_config = esp_radio::wifi::Config::Station(
        esp_radio::wifi::sta::StationConfig::default()
            .with_ssid(config::WIFI_SSID)
            .with_password(config::WIFI_PASS.into()),
    );
    wifi_controller.set_config(&station_config).unwrap();

    // 6. Initialize the network stack.
    let rng = esp_hal::rng::Rng::new();
    let seed = ((rng.random() as u64) << 32) | (rng.random() as u64);

    static RESOURCES: StaticCell<StackResources<5>> = StaticCell::new();
    let resources = RESOURCES.init(StackResources::<5>::new());

    let (stack, runner) = embassy_net::new(
        interfaces.station,
        embassy_net::Config::dhcpv4(Default::default()),
        resources,
        seed,
    );

    spawner.spawn(net_task(runner).unwrap());

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
    let mut pn532 = match nfc::init_pn532(i2c) {
        Ok(p) => {
            println!("PN532 initialized successfully!");
            Some(p)
        }
        Err(e) => {
            println!("PN532 init failed: {:?} — continuing without NFC", e);
            None
        }
    };

    // 8. Persistent MQTT/TCP buffers and topic names.
    let mut mqtt_rx_buf = [0u8; 1024];
    let mut mqtt_tx_buf = [0u8; 1024];
    let mut tcp_rx_buf = [0u8; 1024];
    let mut tcp_tx_buf = [0u8; 1024];

    let mut auth_topic = heapless::String::<96>::new();
    let mut cmd_topic = heapless::String::<96>::new();
    let mut presence_topic = heapless::String::<96>::new();
    let _ = write!(&mut auth_topic, "access/{}/auth", config::DEVICE_ID);
    let _ = write!(&mut cmd_topic, "access/{}/cmd", config::DEVICE_ID);
    let _ = write!(&mut presence_topic, "access/{}/presence", config::DEVICE_ID);

    let broker_port: u16 = config::MQTT_PORT.parse().unwrap_or(1883);
    let mut backoff_secs: u64 = 1;

    fn next_backoff(secs: &mut u64) -> u64 {
        let current = *secs;
        *secs = match current {
            1 => 2,
            2 => 5,
            _ => 15,
        };
        current
    }

    // 9. Active Wi-Fi / MQTT reconnection loop.
    loop {
        status_led::set_state(status_led::LedState::WifiConnecting);

        if !wifi_controller.is_connected() {
            println!("Connecting to WiFi...");
            match wifi_controller.connect_async().await {
                Ok(_) => println!("WiFi connected"),
                Err(e) => {
                    println!("WiFi connection failed: {:?}", e);
                    Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                    continue;
                }
            }
        }

        // Wait for DHCP (max 15 s before retrying).
        let mut dhcp_ok = false;
        for _ in 0..30 {
            if stack.config_v4().is_some() {
                dhcp_ok = true;
                break;
            }
            Timer::after(Duration::from_millis(500)).await;
        }
        if !dhcp_ok {
            println!("DHCP timeout — retrying...");
            Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
            continue;
        }

        let ip_info = stack.config_v4().unwrap();
        println!("IP: {}", ip_info.address);

        // Resolve the broker. `dns_query` also accepts IP literals.
        let broker_addr =
            match stack.dns_query(config::MQTT_HOST, embassy_net::dns::DnsQueryType::A).await {
                Ok(addrs) if !addrs.is_empty() => addrs[0],
                Ok(_) => {
                    println!("DNS returned no addresses for {}", config::MQTT_HOST);
                    Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                    continue;
                }
                Err(e) => {
                    println!("DNS lookup failed for {}: {:?}", config::MQTT_HOST, e);
                    Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                    continue;
                }
            };
        println!("Broker {} -> {}:{}", config::MQTT_HOST, broker_addr, broker_port);

        // Open the TCP transport.
        let mut socket = TcpSocket::new(stack, &mut tcp_rx_buf, &mut tcp_tx_buf);
        match socket.connect((broker_addr, broker_port)).await {
            Ok(_) => println!("TCP connected to MQTT broker."),
            Err(e) => {
                println!("TCP connection to broker failed: {:?}", e);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                continue;
            }
        }

        // Build the MQTT session: authenticated, with a retained "offline" LWT.
        let will = match Will::new(presence_topic.as_str(), b"offline", &[]) {
            Ok(w) => w.retained(),
            Err(e) => {
                println!("Invalid LWT configuration: {:?}", e);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                continue;
            }
        };
        let mqtt_config =
            match ConfigBuilder::new(Buffers::new(&mut mqtt_rx_buf, &mut mqtt_tx_buf))
                .client_id(config::DEVICE_ID)
                .and_then(|c| c.auth(config::MQTT_USER, config::MQTT_PASSWORD.as_bytes()))
                .and_then(|c| c.will(will))
            {
                Ok(c) => c,
                Err(e) => {
                    println!("Invalid MQTT configuration: {:?}", e);
                    Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                    continue;
                }
            };
        let mut session = Session::new(mqtt_config);

        match session.connect(socket).await {
            Ok(ConnectEvent::Connected) | Ok(ConnectEvent::Reconnected) => {
                println!("MQTT connected! Entering active tag reading loop...");
                status_led::set_state(status_led::LedState::MqttConnected);

                // Connection is healthy again — reset the reconnect backoff.
                backoff_secs = 1;

                // Announce presence (retained so late subscribers see "online").
                let online = Publication::new(presence_topic.as_str(), "online").retain();
                if let Err(e) = session.publish(online).await {
                    println!("presence publish failed: {:?}", e);
                }

                // Subscribe to this device's command topic.
                let filters = [TopicFilter::new(cmd_topic.as_str())];
                if let Err(e) = session.subscribe(&filters, &[]).await {
                    println!("subscribe failed: {:?}", e);
                    status_led::set_state(status_led::LedState::DeniedOrOffline);
                    Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                    continue;
                }

                let mut debounce = tag_debounce::TagDebounce::new();
                let mut ndef_buf = [0u8; 256];

                loop {
                    // Drive MQTT with a bounded wait so NFC polling keeps flowing.
                    match embassy_time::with_timeout(
                        Duration::from_millis(20),
                        session.poll(),
                    )
                    .await
                    {
                        Ok(Ok(Some(msg))) => match cmd::parse_cmd_slice(msg.payload()) {
                            Ok(c) => {
                                if c.grant {
                                    let _ = relay::RELAY_CHANNEL.try_send(c.pulse_ms);
                                    status_led::set_state(status_led::LedState::Grant);
                                    println!("GRANT ({} ms): {}", c.pulse_ms, c.reason);
                                } else {
                                    status_led::set_state(status_led::LedState::DeniedOrOffline);
                                    println!("DENY: {}", c.reason);
                                }
                            }
                            Err(e) => println!("cmd parse error: {:?}", e),
                        },
                        Ok(Ok(None)) => {}
                        Ok(Err(e)) => {
                            println!("MQTT poll error: {:?}", e);
                            break;
                        }
                        Err(_) => {} // No inbound packet within the window.
                    }

                    // Poll NFC and run the edge-triggered debounce state machine.
                    if let Some(ref mut pn) = pn532 {
                        let tag_opt = nfc::poll_tag(pn);
                        let obs = tag_opt
                            .as_ref()
                            .map(tag_debounce::TagObservation::from_tag_info);
                        let now = Instant::now();

                        if let Some(ev) = debounce.observe(now, obs) {
                            // SAK 0x20 => ISO 14443-4 (DESFire / NTAG 424 DNA).
                            if ev.sak == 0x20 {
                                status_led::set_state(status_led::LedState::TagReading);

                                let read_res = {
                                    let pn_ref: &mut _ = &mut *pn;
                                    let mut exchange =
                                        move |apdu: &[u8], out: &mut [u8]| -> Result<usize, ntag424::NdefError> {
                                            let resp = nfc::in_data_exchange(pn_ref, 1, apdu)
                                                .map_err(|_| ntag424::NdefError::Transport)?;
                                            if out.len() < resp.len() {
                                                return Err(ntag424::NdefError::BufferTooSmall);
                                            }
                                            out[..resp.len()].copy_from_slice(resp);
                                            Ok(resp.len())
                                        };
                                    ntag424::read_ndef_message(&mut exchange, &mut ndef_buf)
                                };

                                match read_res {
                                    Ok(n) => match ntag424::extract_ndef_uri(&ndef_buf[..n]) {
                                        Ok(uri) => match ntag424::parse_sun_url(uri) {
                                            Ok(sun) => {
                                                let mut payload = heapless::String::<256>::new();
                                                match auth_msg::build_auth_json(
                                                    config::DEVICE_ID,
                                                    &sun,
                                                    &mut payload,
                                                ) {
                                                    Ok(()) => {
                                                        let tag = tag_opt.as_ref().unwrap();
                                                        println!(
                                                            "auth: {} uid={} ctr={}",
                                                            tag.tag_type(), tag.uid_hex(), sun.counter
                                                        );
                                                        let pkt = Publication::new(
                                                            auth_topic.as_str(),
                                                            payload.as_str(),
                                                        );
                                                        match session.publish(pkt).await {
                                                            Ok(_) => println!("auth published"),
                                                            Err(e) => {
                                                                println!(
                                                                    "auth publish failed: {:?}",
                                                                    e
                                                                );
                                                                break;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        println!("auth json error: {:?}", e);
                                                        status_led::set_state(
                                                            status_led::LedState::DeniedOrOffline,
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                println!("SUN parse error: {:?}", e);
                                                status_led::set_state(
                                                    status_led::LedState::DeniedOrOffline,
                                                );
                                            }
                                        },
                                        Err(e) => {
                                            println!("NDEF uri error: {:?}", e);
                                            status_led::set_state(
                                                status_led::LedState::DeniedOrOffline,
                                            );
                                        }
                                    },
                                    Err(e) => {
                                        println!("NDEF read error: {:?}", e);
                                        status_led::set_state(
                                            status_led::LedState::DeniedOrOffline,
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Cooperative yield to keep the executor responsive.
                    Timer::after(Duration::from_millis(30)).await;
                }
            }
            Err(e) => {
                println!("MQTT session connect failed: {:?}", e);
                status_led::set_state(status_led::LedState::DeniedOrOffline);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
            }
        }
    }
}
