//! XIAO ESP32-C6 — Screenless NFC Reader Node
//!
//! Bare-metal Rust firmware for Seeed Studio XIAO ESP32-C6 boards.
//! Each node reads NFC tags via a PN532 (I2C) and publishes them to MQTT.

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

use embassy_executor::Spawner;
use embassy_net::{tcp::TcpSocket, StackResources};
use embassy_time::{Duration, Instant, Timer};
use minimq::{Buffers, ConfigBuilder, ConnectEvent, Session, Publication};
use static_cell::StaticCell;
use core::fmt::Write;

mod ntag424;
mod nfc;

// Provide the application descriptor for the second-stage bootloader
esp_bootloader_esp_idf::esp_app_desc!();

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, esp_radio::wifi::Interface<'static>>) -> ! {
    runner.run().await
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    // 1. Initialize Heap Allocator (72KB)
    esp_alloc::heap_allocator!(size: 72 * 1024);

    // 2. Initialize Peripherals
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // 3. Initialize RTOS Scheduler
    let timg0 = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt = esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_interrupt.software_interrupt0);

    // Initialize amber LED on GPIO15 (active-low: set_low = ON, set_high = OFF)
    let mut led = Output::new(peripherals.GPIO15, Level::High, OutputConfig::default());

    println!("XIAO-C6 NFC node starting...");

    // 4. Initialize Wi-Fi
    println!("Configuring WiFi...");
    let (mut wifi_controller, interfaces) = esp_radio::wifi::new(
        peripherals.WIFI,
        esp_radio::wifi::ControllerConfig::default(),
    )
    .unwrap();

    let station_config = esp_radio::wifi::Config::Station(
        esp_radio::wifi::sta::StationConfig::default()
            .with_ssid("10bitworks")
            .with_password("10bitrocks".into())
    );
    wifi_controller.set_config(&station_config).unwrap();

    // 5. Initialize Network Stack
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

    // 6. Initialize I2C for PN532
    // XIAO ESP32-C6 pinout: D4 = GPIO2 (SDA), D5 = GPIO3 (SCL)
    let i2c = I2c::new(
        peripherals.I2C0,
        I2cConfig::default().with_frequency(Rate::from_khz(100)),
    )
    .unwrap()
    .with_sda(peripherals.GPIO2)
    .with_scl(peripherals.GPIO3);

    println!("I2C initialized on GPIO2 (SDA) / GPIO3 (SCL)");

    // Initialize the PN532 module (non-fatal — WiFi/MQTT proceed regardless)
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

    // 7. Active Wi-Fi & MQTT Reconnection and Polling Loop
    let mut mqtt_rx_buf = [0u8; 1024];
    let mut mqtt_tx_buf = [0u8; 1024];
    let mut tcp_rx_buf = [0u8; 1024];
    let mut tcp_tx_buf = [0u8; 1024];

    loop {
        // Try to connect to WiFi if not connected
        if !wifi_controller.is_connected() {
            println!("Connecting to WiFi...");
            // Slow blink while connecting to WiFi
            led.set_low(); // ON
            Timer::after(Duration::from_millis(500)).await;
            led.set_high(); // OFF
            match wifi_controller.connect_async().await {
                Ok(_) => {
                    println!("WiFi connected");
                }
                Err(e) => {
                    println!("WiFi connection failed: {:?}", e);
                    // Blink error pattern: 3 quick flashes
                    for _ in 0..3 {
                        led.set_low();
                        Timer::after(Duration::from_millis(100)).await;
                        led.set_high();
                        Timer::after(Duration::from_millis(100)).await;
                    }
                    Timer::after(Duration::from_secs(5)).await;
                    continue;
                }
            }
        }

        // Wait for DHCP (max 15 seconds before retrying)
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
            Timer::after(Duration::from_secs(2)).await;
            continue;
        }

        let ip_info = stack.config_v4().unwrap();
        println!("IP: {}", ip_info.address);

        // Fast blink: WiFi up, connecting to MQTT
        led.set_low();
        Timer::after(Duration::from_millis(100)).await;
        led.set_high();
        Timer::after(Duration::from_millis(100)).await;
        led.set_low();

        // Resolve MQTT broker hostname via DNS
        let broker_host = "broker.10bit";
        let broker_port = 1883;
        let broker_addr = match stack.dns_query(broker_host, embassy_net::dns::DnsQueryType::A).await {
            Ok(addrs) if !addrs.is_empty() => addrs[0],
            Ok(_) => {
                println!("DNS resolved {} but got no addresses", broker_host);
                Timer::after(Duration::from_secs(5)).await;
                continue;
            }
            Err(e) => {
                println!("DNS lookup failed for {}: {:?}", broker_host, e);
                Timer::after(Duration::from_secs(5)).await;
                continue;
            }
        };
        println!("Resolved {} -> {}", broker_host, broker_addr);

        // Open TCP connection to MQTT broker
        let mut socket = TcpSocket::new(stack, &mut tcp_rx_buf, &mut tcp_tx_buf);
        println!("Connecting TCP to {}:{}...", broker_host, broker_port);

        match socket.connect((broker_addr, broker_port)).await {
            Ok(_) => {
                println!("TCP connected to MQTT broker.");
            }
            Err(e) => {
                println!("TCP connection to broker failed: {:?}", e);
                Timer::after(Duration::from_secs(5)).await;
                continue;
            }
        }

        // Connect the MQTT session
        let mut session = Session::new(
            ConfigBuilder::new(Buffers::new(&mut mqtt_rx_buf, &mut mqtt_tx_buf))
                .client_id("xiao-c6-nfc")
                .unwrap(),
        );

        match session.connect(socket).await {
            Ok(ConnectEvent::Connected) | Ok(ConnectEvent::Reconnected) => {
                println!("MQTT connected! Entering active tag reading loop...");
                led.set_low(); // Solid ON — fully connected

                // Active NFC read & publish loop
                let mut last_uid: Option<([u8; 7], u8)> = None;
                let mut cooldown_until = Instant::now();
                let mut next_heartbeat = Instant::now(); // Send first heartbeat immediately
                let nfc_status = if pn532.is_some() { "ok" } else { "absent" };
                let ip_str = {
                    let mut s = heapless::String::<20>::new();
                    let _ = write!(&mut s, "{}", ip_info.address);
                    s
                };

                loop {
                    // Drive MQTT keepalives
                    let _ = embassy_time::with_timeout(
                        Duration::from_millis(50),
                        session.poll()
                    ).await;

                    // Publish heartbeat every 30 seconds
                    let now = Instant::now();
                    if now >= next_heartbeat {
                        next_heartbeat = now + Duration::from_secs(30);
                        let uptime_secs = now.as_millis() / 1000;
                        let mut hb = heapless::String::<128>::new();
                        if write!(
                            &mut hb,
                            "{{\"uptime\":{},\"ip\":\"{}\",\"nfc\":\"{}\"}}",
                            uptime_secs, ip_str.as_str(), nfc_status
                        ).is_ok() {
                            let pub_pkt = Publication::new("xiao-c6/status", hb.as_str());
                            if let Err(e) = session.publish(pub_pkt).await {
                                println!("Heartbeat publish failed: {:?}", e);
                                break;
                            }
                        }
                    }

                    // Poll for tag (only if PN532 is available)
                    let mut tag_seen = false;
                    if let Some(ref mut pn) = pn532 {
                        if let Some(tag) = nfc::poll_tag(pn) {
                            tag_seen = true;
                            let now = Instant::now();
                            let is_repeat = last_uid.map_or(false, |(prev, prev_len)| {
                                prev_len == tag.uid_len
                                    && prev[..prev_len as usize] == tag.uid[..tag.uid_len as usize]
                            });

                            if !is_repeat || now >= cooldown_until {
                                last_uid = Some((tag.uid, tag.uid_len));
                                cooldown_until = now + Duration::from_secs(3);

                                let mut payload = heapless::String::<128>::new();
                                if write!(
                                    &mut payload,
                                    "{{\"uid\":\"{}\",\"sak\":{},\"type\":\"{}\"}}",
                                    tag.uid_hex(),
                                    tag.sak,
                                    tag.tag_type()
                                )
                                .is_ok()
                                {
                                    // Brief flash off/on to signal tag read
                                    led.set_high();
                                    Timer::after(Duration::from_millis(50)).await;
                                    led.set_low();
                                    println!("Tag: {}", payload.as_str());

                                    let pub_pkt = Publication::new("xiao-c6/nfc", payload.as_str());
                                    match session.publish(pub_pkt).await {
                                        Ok(_) => println!("Published."),
                                        Err(e) => {
                                            println!("MQTT publish failed: {:?}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                        } else {
                            // Tag removed — reset debounce
                            last_uid = None;
                        }
                    }

                    // Adaptive yield: shorter when tag present, longer when idle
                    // to reduce executor starvation from blocking I2C polls
                    if tag_seen {
                        Timer::after(Duration::from_millis(100)).await;
                    } else {
                        Timer::after(Duration::from_millis(250)).await;
                    }
                }
            }
            Err(e) => {
                println!("MQTT session connect failed: {:?}", e);
                led.set_high(); // LED off on disconnect
                Timer::after(Duration::from_secs(5)).await;
            }
        }
    }
}
