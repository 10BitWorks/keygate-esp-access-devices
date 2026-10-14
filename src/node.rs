//! Decoupled NFC and MQTT Node Lifecycle.
//!
//! Separates NFC tag reading from Wi-Fi and MQTT connectivity:
//! - `nfc_runner`: Runs continuously and independently. Polls PN532, handles
//!   tag debouncing, SUN extraction, blank tag resilience, and beeps.
//!   Works completely offline without Wi-Fi or broker connectivity.
//! - `mqtt_runner`: Manages Wi-Fi association, DHCP, MQTT session lifecycle,
//!   incoming door commands (`cmd_topic`), and drains the outgoing auth queue.

use core::fmt::Write;
use embassy_futures::select::{select4, Either4};
use embassy_net::tcp::TcpSocket;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
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
    provision, provision_flow::ProvState,
    relay, status_led, tag_debounce,
};
use crate::piezo::{self, BeepEvent};
use crate::piezo::PIEZO_CHANNEL as PZ;

/// Outbound authentication requests from the independent NFC reader to MQTT.
/// Capacity 8 buffers taps during brief network disconnects or broker retries.
pub static AUTH_OUTBOUND: Channel<CriticalSectionRawMutex, heapless::String<256>, 8> = Channel::new();

/// Pending provisioning job dispatched from MQTT to the NFC task.
pub static PROV_JOB: Mutex<CriticalSectionRawMutex, Option<(heapless::String<32>, heapless::String<32>)>> =
    Mutex::new(None);

/// Outbound provisioning claim requests from NFC to MQTT.
pub static PROV_CLAIM_OUTBOUND: Channel<CriticalSectionRawMutex, heapless::String<128>, 2> = Channel::new();

/// Outbound provisioning done reports from NFC to MQTT: `(job_id, ok, counter, error_str)`.
pub static PROV_DONE_OUTBOUND: Channel<
    CriticalSectionRawMutex,
    (heapless::String<32>, bool, u32, &'static str),
    2,
> = Channel::new();

/// Main node entry point running both decoupled runners concurrently.
pub async fn run<I: pn532::Interface>(
    pn532: Option<Pn532<I, Pn532Delay, 300>>,
    reader_reset: Option<esp_hal::gpio::Output<'static>>,
    stack: embassy_net::Stack<'static>,
    wifi_controller: esp_radio::wifi::WifiController<'static>,
) -> ! {
    embassy_futures::join::join(
        nfc_runner(pn532, reader_reset),
        mqtt_runner(stack, wifi_controller),
    )
    .await;

    loop {
        Timer::after(Duration::from_secs(60)).await;
    }
}

/// Helper to decode 32-hex ASCII characters into a 16-byte raw key.
fn decode_key16(hex: &str, out: &mut [u8; 16]) -> bool {
    let b = hex.as_bytes();
    if b.len() != 32 {
        return false;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = match nib(b[2 * i]) {
            Some(v) => v,
            None => return false,
        };
        let lo = match nib(b[2 * i + 1]) {
            Some(v) => v,
            None => return false,
        };
        *byte = (hi << 4) | lo;
    }
    true
}

// ---------------------------------------------------------------------------
// NFC Reader Runner (Completely Offline Capable)
// ---------------------------------------------------------------------------

async fn nfc_runner<I: pn532::Interface>(
    mut pn532: Option<Pn532<I, Pn532Delay, 300>>,
    mut reader_reset: Option<esp_hal::gpio::Output<'static>>,
) -> ! {
    let mut debounce = tag_debounce::TagDebounce::new();
    let mut ndef_buf = [0u8; 256];
    let mut no_nfc_logged = false;

    println!("[nfc] reader task started (independent from network)");

    loop {
        if let Some(ref mut pn) = pn532 {
            no_nfc_logged = false;
            let now = Instant::now();

            // Periodic liveness check: verify SPI bus integrity via GetFirmwareVersion.
            {
                use core::sync::atomic::{AtomicU32, Ordering};
                static HEALTH_N: AtomicU32 = AtomicU32::new(0);
                let it = HEALTH_N.fetch_add(1, Ordering::Relaxed);
                if it % 50 == 0 {
                    if let Err(e) = nfc::health_check(pn) {
                        println!("[nfc] bus health check FAILED ({:?}) — pulsing RSTO", e);
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

            // Fast, non-blocking poll (200 ms timeout in driver, returns Option<TagInfo>).
            let tag_opt = nfc::poll_tag(pn);
            let obs = tag_opt.as_ref().map(tag_debounce::TagObservation::from_tag_info);

            if let Some(ev) = debounce.observe(now, obs) {
                // Audible feedback: immediate beep on every physical tag detection.
                let _ = PZ.try_send(BeepEvent::TagDetected);

                // SAK 0x20 => ISO 14443-4 (DESFire / NTAG 424 DNA).
                if ev.sak == 0x20 {
                    status_led::set_state(status_led::LedState::TagReading);

                    // Check if an admin provisioning job is active.
                    let pending_job = {
                        let lock = PROV_JOB.lock().await;
                        lock.clone()
                    };

                    if let Some((job_id, key_hex)) = pending_job {
                        println!("[prov] executing tag provisioning for job {}...", job_id);
                        let mut rnda = [0u8; 16];
                        let mut rng = esp_hal::rng::Rng::new();
                        for chunk in rnda.chunks_mut(4) {
                            let w = rng.random().to_le_bytes();
                            chunk.copy_from_slice(&w[..chunk.len()]);
                        }
                        let mut key = [0u8; 16];
                        let run = if decode_key16(key_hex.as_str(), &mut key) {
                            let mut report = provision::ProvisionReport { uid: [0; 7], counter: 0 };
                            let pn_ref: &mut _ = &mut *pn;
                            let mut exchange = move |apdu: &[u8], out: &mut [u8]| -> Result<usize, ntag424::NdefError> {
                                let resp = nfc::in_data_exchange(pn_ref, 1, apdu)
                                    .map_err(|_| ntag424::NdefError::Transport)?;
                                if out.len() < resp.len() {
                                    return Err(ntag424::NdefError::BufferTooSmall);
                                }
                                out[..resp.len()].copy_from_slice(resp);
                                Ok(resp.len())
                            };
                            provision::provision_tag(
                                &mut exchange,
                                &rnda,
                                &key,
                                config::PROVISION_URL_TEMPLATE,
                                &mut report,
                            )
                            .map(|_| report)
                        } else {
                            Err(provision::ProvisionError::BadTemplate)
                        };

                        let (ok, counter, reason) = match &run {
                            Ok(report) => (true, report.counter, ""),
                            Err(e) => {
                                println!("[prov] provision error: {:?}", e);
                                (false, 0, "provision error")
                            }
                        };

                        // Clear job after one execution attempt.
                        {
                            let mut lock = PROV_JOB.lock().await;
                            *lock = None;
                        }

                        let _ = PROV_DONE_OUTBOUND.try_send((job_id, ok, counter, reason));
                        if ok {
                            let _ = PZ.try_send(BeepEvent::Granted);
                            status_led::set_state(status_led::LedState::Grant);
                        } else {
                            let _ = PZ.try_send(BeepEvent::Denied);
                            status_led::set_state(status_led::LedState::DeniedOrOffline);
                        }
                    } else {
                        // Standard authentication path: read NDEF message.
                        let read_res = {
                            let pn_ref: &mut _ = &mut *pn;
                            let mut exchange = move |apdu: &[u8], out: &mut [u8]| -> Result<usize, ntag424::NdefError> {
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
                                        if auth_msg::build_auth_json(config::DEVICE_ID, &sun, &mut payload).is_ok() {
                                            println!(
                                                "auth: {} uid:{} ctr:{}",
                                                ev.uid_len,
                                                nfc::TagInfo { uid: ev.uid, uid_len: ev.uid_len, sak: ev.sak }.uid_hex(),
                                                sun.counter
                                            );
                                            // Enqueue for publishing when MQTT is online.
                                            let _ = AUTH_OUTBOUND.try_send(payload);
                                            let _ = PZ.try_send(BeepEvent::AuthSent);
                                        }
                                        status_led::set_state(status_led::LedState::MqttConnected);
                                    }
                                    Err(e) => {
                                        println!("SUN parse error: {:?}", e);
                                        status_led::set_state(status_led::LedState::MqttConnected);
                                    }
                                },
                                Err(e) => {
                                    println!("NDEF URI error: {:?}", e);
                                    status_led::set_state(status_led::LedState::MqttConnected);
                                }
                            },
                            Err(e) => {
                                // Blank / unwritten tag — perfectly normal.
                                println!("NDEF read: unwritten/blank tag ({:?})", e);
                                status_led::set_state(status_led::LedState::MqttConnected);
                            }
                        }
                    }

                    // Reset RF field so any tag remaining on the antenna power-cycles
                    // back to ISO-14443-3 Idle for clean subsequent polling.
                    nfc::cycle_rf_field(pn);
                }
            }
        } else {
            if !no_nfc_logged {
                println!("[nfc] no reader initialized — idling NFC polling");
                no_nfc_logged = true;
            }
            Timer::after(Duration::from_secs(1)).await;
        }

        // Cooperative yield to executor tasks.
        Timer::after(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// MQTT & Wi-Fi Runner (Network & Broker Management)
// ---------------------------------------------------------------------------

async fn mqtt_runner(
    stack: embassy_net::Stack<'static>,
    mut wifi_controller: esp_radio::wifi::WifiController<'static>,
) -> ! {
    let mut mqtt_rx_buf = [0u8; 1024];
    let mut mqtt_tx_buf = [0u8; 1024];
    let mut tcp_rx_buf = [0u8; 1024];
    let mut tcp_tx_buf = [0u8; 1024];

    let mut auth_topic = heapless::String::<96>::new();
    let mut cmd_topic = heapless::String::<96>::new();
    let mut log_topic = heapless::String::<96>::new();
    let mut presence_topic = heapless::String::<96>::new();
    let mut job_topic = heapless::String::<96>::new();
    let mut claim_topic = heapless::String::<96>::new();
    let mut done_topic = heapless::String::<96>::new();

    let _ = write!(&mut auth_topic, "access/{}/auth", config::DEVICE_ID);
    let _ = write!(&mut cmd_topic, "access/{}/cmd", config::DEVICE_ID);
    let _ = write!(&mut presence_topic, "access/{}/presence", config::DEVICE_ID);
    let _ = write!(&mut log_topic, "access/{}/log", config::DEVICE_ID);
    let _ = write!(&mut job_topic, "writer/{}/job", config::DEVICE_ID);
    let _ = write!(&mut claim_topic, "writer/{}/claim", config::DEVICE_ID);
    let _ = write!(&mut done_topic, "writer/{}/done", config::DEVICE_ID);

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

    loop {
        // Audible connection progress: joining Wi-Fi first.
        piezo::set_conn_state(piezo::conn::WAIT_WIFI);
        status_led::set_state(status_led::LedState::WifiConnecting);

        if !wifi_controller.is_connected() {
            println!("Connecting to WiFi...");
            match wifi_controller.connect_async().await {
                Ok(_) => println!("WiFi connected"),
                Err(e) => {
                    blog!("WiFi connection failed: {:?}", e);
                    Timer::after(Duration::from_secs(1)).await;
                    continue;
                }
            }
        }

        // Wait for DHCP (up to 30 s with 500 ms poll).
        let mut dhcp_ok = false;
        for _ in 0..60 {
            if stack.config_v4().is_some() {
                dhcp_ok = true;
                break;
            }
            Timer::after(Duration::from_millis(500)).await;
        }
        if !dhcp_ok {
            blog!("DHCP timeout — retrying...");
            Timer::after(Duration::from_secs(1)).await;
            continue;
        }

        let ip_info = stack.config_v4().unwrap();
        println!("IP: {}", ip_info.address);

        // Wi-Fi + DHCP up; audible progress moves to MQTT joining.
        piezo::set_conn_state(piezo::conn::WAIT_MQTT);

        // Resolve broker address.
        let broker_addr = match stack.dns_query(config::MQTT_HOST, embassy_net::dns::DnsQueryType::A).await {
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

        // Open TCP transport.
        let mut socket = TcpSocket::new(stack, &mut tcp_rx_buf, &mut tcp_tx_buf);
        match socket.connect((broker_addr, broker_port)).await {
            Ok(_) => println!("TCP connected to MQTT broker."),
            Err(e) => {
                println!("TCP connection to broker failed: {:?}", e);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                continue;
            }
        }

        // Build MQTT session with retained offline LWT.
        let will = match Will::new(presence_topic.as_str(), b"offline", &[]) {
            Ok(w) => w.retained(),
            Err(e) => {
                println!("Invalid LWT configuration: {:?}", e);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                continue;
            }
        };

        let mqtt_config = match ConfigBuilder::new(Buffers::new(&mut mqtt_rx_buf, &mut mqtt_tx_buf))
            .client_id(config::DEVICE_ID)
            .and_then(|c| c.auth(config::DEVICE_ID, config::MQTT_PASSWORD.as_bytes()))
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
                println!("MQTT connected! Broker online.");
                status_led::set_state(status_led::LedState::MqttConnected);
                backoff_secs = 1;

                // Flush buffered diagnostics (bounded, max 4 lines).
                let mut flushed = 0u8;
                while flushed < 4 {
                    let Some(line) = crate::diag::imp::pop() else {
                        break;
                    };
                    flushed += 1;
                    let pkt = Publication::new(log_topic.as_str(), line.as_str());
                    if session.publish(pkt).await.is_err() {
                        break;
                    }
                }
                while crate::diag::imp::pop().is_some() {}

                // Announce retained online presence.
                let online = Publication::new(presence_topic.as_str(), "online").retain();
                let _ = session.publish(online).await;

                // Audible confirmation: online.
                piezo::set_conn_state(piezo::conn::ONLINE);

                // Subscribe to command and provisioning topics.
                let cmd_filters = [TopicFilter::new(cmd_topic.as_str())];
                if session.subscribe(&cmd_filters, &[]).await.is_err() {
                    status_led::set_state(status_led::LedState::DeniedOrOffline);
                    Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                    continue;
                }

                let job_filters = [TopicFilter::new(job_topic.as_str())];
                if session.subscribe(&job_filters, &[]).await.is_err() {
                    status_led::set_state(status_led::LedState::DeniedOrOffline);
                    Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                    continue;
                }

                // Inner connected MQTT pump loop driven by select4.
                loop {
                    match select4(
                        session.poll(),
                        AUTH_OUTBOUND.receive(),
                        PROV_CLAIM_OUTBOUND.receive(),
                        PROV_DONE_OUTBOUND.receive(),
                    )
                    .await
                    {
                        Either4::First(poll_res) => match poll_res {
                            Ok(Some(msg)) => {
                                let topic = msg.topic();
                                let payload = msg.payload();

                                if topic == cmd_topic.as_str() {
                                    if let Ok(c) = cmd::parse_cmd_slice(payload) {
                                        if c.grant {
                                            let _ = relay::RELAY_CHANNEL.try_send(c.pulse_ms);
                                            let _ = PZ.try_send(BeepEvent::RelayPulse);
                                            let _ = PZ.try_send(BeepEvent::Granted);
                                            status_led::set_state(status_led::LedState::Grant);
                                            println!("GRANT ({} ms): {}", c.pulse_ms, c.reason);
                                        } else {
                                            let _ = PZ.try_send(BeepEvent::Denied);
                                            status_led::set_state(status_led::LedState::DeniedOrOffline);
                                            println!("DENY: {}", c.reason);
                                        }
                                    }
                                } else if topic == job_topic.as_str() {
                                    if let Ok(text) = core::str::from_utf8(payload) {
                                        if let Ok((job_p, _)) =
                                            serde_json_core::from_str::<crate::provision_flow::JobPayload>(text)
                                        {
                                            println!("[prov] received job: {}", job_p.job_id);
                                            let mut j_id = heapless::String::<32>::new();
                                            let mut j_key = heapless::String::<32>::new();
                                            let _ = j_id.push_str(job_p.job_id);
                                            let _ = j_key.push_str(job_p.key);
                                            let mut lock = PROV_JOB.lock().await;
                                            *lock = Some((j_id, j_key));
                                            let _ = PZ.try_send(BeepEvent::ProvisionArmed);
                                        }
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                println!("[mqtt] session poll error: {:?}", e);
                                blog!("mqtt poll error: {:?}", e);
                                break;
                            }
                        },
                        Either4::Second(auth_payload) => {
                            let pkt = Publication::new(auth_topic.as_str(), auth_payload.as_str());
                            if let Err(e) = session.publish(pkt).await {
                                println!("[mqtt] auth publish error: {:?}", e);
                                break;
                            }
                        }
                        Either4::Third(claim_payload) => {
                            let pkt = Publication::new(claim_topic.as_str(), claim_payload.as_str())
                                .qos(minimq::QoS::AtLeastOnce);
                            let _ = session.publish(pkt).await;
                        }
                        Either4::Fourth((job_id, ok, counter, reason)) => {
                            let done = crate::provision_flow::build_done_json(job_id.as_str(), ok, counter, reason);
                            let pkt = Publication::new(done_topic.as_str(), done.as_str())
                                .qos(minimq::QoS::AtLeastOnce);
                            let _ = session.publish(pkt).await;
                        }
                    }
                }

                // If inner loop exits, session dropped.
                piezo::set_conn_state(piezo::conn::RECONNECT);
                let wait = next_backoff(&mut backoff_secs);
                blog!("mqtt session dropped — reconnect in {}s", wait);
                Timer::after(Duration::from_secs(wait)).await;
            }
            Err(e) => {
                blog!("MQTT session connect failed: {:?}", e);
                status_led::set_state(status_led::LedState::DeniedOrOffline);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
            }
        }
    }
}
