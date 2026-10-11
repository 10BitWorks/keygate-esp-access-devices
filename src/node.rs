//! Reconnect, MQTT pub/sub, and NFC tap loop.
//!
//! Encapsulates the runtime node lifecycle: Wi-Fi connection, DHCP acquisition,
//! MQTT session management, LWT presence, incoming command actuation,
//! and NTAG 424 DNA SUN reading.

use core::fmt::Write;
use embassy_net::tcp::TcpSocket;
use embassy_time::{Duration, Instant, Timer};
use esp_println::println;
use minimq::{
    Buffers, ConfigBuilder, ConnectEvent, Publication, Session, TopicFilter, Will,
};
use pn532::Pn532;

use crate::{
    auth_msg, cmd, config,
    nfc::{self, Pn532Delay},
    ntag424,
    reader_supervisor::{Action, ResetPolicy},
    relay, status_led, tag_debounce,
};

pub async fn run<I: pn532::Interface>(
    mut pn532: Option<Pn532<I, Pn532Delay, 300>>,
    mut reader_reset: Option<esp_hal::gpio::Output<'static>>,
    stack: embassy_net::Stack<'static>,
    mut wifi_controller: esp_radio::wifi::WifiController<'static>,
) -> ! {

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
                let mut policy = ResetPolicy::new();
                let mut no_nfc_logged = false;

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
                        no_nfc_logged = false;
                        let now = Instant::now();
                        let now_ms = now.as_millis() as u64;

                        match nfc::poll_tag(pn) {
                            Ok(tag_opt) => {
                                policy.observe(false, now_ms);

                                let obs = tag_opt
                                    .as_ref()
                                    .map(tag_debounce::TagObservation::from_tag_info);

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
                                                                if let Some(tag) = tag_opt.as_ref() {
                                                                    println!(
                                                                        "auth: {} uid:{} ctr:{}",
                                                                        tag.tag_type(),
                                                                        tag.uid_hex(),
                                                                        sun.counter
                                                                    );
                                                                }
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
                            Err(e) => {
                                if policy.observe(true, now_ms) == Action::Recover {
                                    println!("[nfc] reader unresponsive ({:?}) — pulsing RSTO + reinit", e);
                                    status_led::set_state(status_led::LedState::DeniedOrOffline);
                                    if let Some(pin) = reader_reset.as_mut() {
                                        pin.set_low();
                                        Timer::after(Duration::from_millis(10)).await;
                                        pin.set_high();
                                        Timer::after(Duration::from_millis(100)).await;
                                    }
                                    let _ = nfc::soft_reinit(pn);
                                }
                            }
                        }
                    } else {
                        if !no_nfc_logged {
                            println!("[nfc] no reader initialized — idling NFC polling");
                            no_nfc_logged = true;
                        }
                        Timer::after(Duration::from_secs(1)).await;
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
