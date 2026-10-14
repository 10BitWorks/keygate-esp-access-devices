//! Decoupled NFC and MQTT Node Lifecycle.
//!
//! Separates NFC tag reading from Wi-Fi and MQTT connectivity:
//! - `nfc_runner`: Runs continuously and independently. Polls PN532, handles
//!   tag debouncing, SUN extraction, blank tag resilience, provisioning, and beeps.
//!   Works completely offline without Wi-Fi or broker connectivity.
//! - `mqtt_runner`: Manages Wi-Fi association, DHCP, MQTT session lifecycle,
//!   incoming door commands (`cmd_topic`), provisioning job routing, and drains
//!   the outgoing auth, claim, and done queues.

use core::fmt::Write;
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
    provision,
    provision_flow::{self, ProvAction, ProvMachine, ProvState},
    relay, status_led, tag_debounce,
};
use crate::piezo::{self, BeepEvent};
use crate::piezo::PIEZO_CHANNEL as PZ;

/// Outbound authentication requests from the independent NFC reader to MQTT.
/// Capacity 8 buffers taps during brief network disconnects or broker retries.
pub static AUTH_OUTBOUND: Channel<CriticalSectionRawMutex, heapless::String<256>, 8> = Channel::new();

/// Outbound provisioning claim requests from NFC to MQTT.
pub static PROV_CLAIM_OUTBOUND: Channel<CriticalSectionRawMutex, heapless::String<128>, 2> = Channel::new();

/// Outbound provisioning done reports from NFC to MQTT: `(job_id, ok, counter, error_str)`.
pub static PROV_DONE_OUTBOUND: Channel<
    CriticalSectionRawMutex,
    (heapless::String<32>, bool, u32, &'static str),
    2,
> = Channel::new();

/// Shared provisioning state machine coordinating the 2-step enrollment protocol between runners.
pub static PROV_MACHINE: Mutex<CriticalSectionRawMutex, ProvMachine> = Mutex::new(ProvMachine::new());

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
            let now_ms = now.as_millis() as u64;

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

            // If in ClaimWait state, wait for the keyed claim reply without polling or cycling RF!
            let (is_claim_wait, prov_ready) = {
                let m = PROV_MACHINE.lock().await;
                (matches!(m.state, ProvState::ClaimWait(..)), m.pending_context())
            };

            if let Some((job_id, key_hex)) = prov_ready {
                println!("[prov] keyed claim reply active — writing card now (job {})", job_id);
                execute_tag_provisioning(pn, &job_id, &key_hex).await;
                nfc::cycle_rf_field(pn);
                continue;
            } else if is_claim_wait {
                // Keep target 1 intact while verifier computes diversified key!
                Timer::after(Duration::from_millis(15)).await;
                continue;
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

                    // Check provisioning state machine:
                    let prov_action = {
                        let mut m = PROV_MACHINE.lock().await;
                        if !m.state.is_idle() {
                            m.on_tap(ev.uid, now_ms, config::CLAIM_WAIT_SECS)
                        } else {
                            ProvAction::None
                        }
                    };

                    match prov_action {
                        ProvAction::PublishClaim(claim) => {
                            println!("[prov] wildcard tap: publishing claim for uid");
                            let _ = PROV_CLAIM_OUTBOUND.try_send(claim);
                        }
                        ProvAction::TapRejected => {
                            println!("[prov] tap rejected (uid mismatch for fixed-uid job)");
                            let _ = PZ.try_send(BeepEvent::Denied);
                        }
                        ProvAction::ProvisionStart => {
                            // Fixed-uid job with pre-provided key
                            let prov_ctx = {
                                let m = PROV_MACHINE.lock().await;
                                m.pending_context()
                            };
                            if let Some((job_id, key_hex)) = prov_ctx {
                                execute_tag_provisioning(pn, &job_id, &key_hex).await;
                                nfc::cycle_rf_field(pn);
                            }
                        }
                        _ => {
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
                        }

                    // Only reset the RF field if not in an active provisioning flow
                    // (the card must remain activated in target slot 1 while awaiting the keyed claim reply).
                    let in_prov = {
                        let m = PROV_MACHINE.lock().await;
                        !m.state.is_idle()
                    };
                    if !in_prov {
                        nfc::cycle_rf_field(pn);
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

        // Cooperative yield to executor tasks.
        Timer::after(Duration::from_millis(15)).await;
    }
}

/// Helper to execute the cryptographic provisioning sequence on the tapped tag.
async fn execute_tag_provisioning<I: pn532::Interface>(
    pn: &mut Pn532<I, Pn532Delay, 300>,
    job_id: &str,
    key_hex: &str,
) {
    println!("[prov] provisioning tag (job {})...", job_id);
    status_led::set_state(status_led::LedState::TagReading);

    let mut rnda = [0u8; 16];
    let mut rng = esp_hal::rng::Rng::new();
    for chunk in rnda.chunks_mut(4) {
        let w = rng.random().to_le_bytes();
        chunk.copy_from_slice(&w[..chunk.len()]);
    }

    let mut key = [0u8; 16];
    let run = if decode_key16(key_hex, &mut key) {
        let mut report = provision::ProvisionReport { uid: [0; 7], counter: 0 };
        let mut exchange = move |apdu: &[u8], out: &mut [u8]| -> Result<usize, ntag424::NdefError> {
            let resp = nfc::in_data_exchange(pn, 1, apdu)
                .map_err(|e| {
                    println!("[exchange] in_data_exchange error: {:?}", e);
                    ntag424::NdefError::Transport
                })?;
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
            println!("[prov] provision sequence error: {:?}", e);
            (false, 0, "provision error")
        }
    };

    let _action = {
        let mut m = PROV_MACHINE.lock().await;
        m.on_provision_done(ok, counter, reason)
    };

    let mut j_id = heapless::String::<32>::new();
    let _ = j_id.push_str(job_id);
    let _ = PROV_DONE_OUTBOUND.try_send((j_id, ok, counter, reason));

    if ok {
        println!("[prov] tag successfully provisioned!");
        let _ = PZ.try_send(BeepEvent::Granted);
        status_led::set_state(status_led::LedState::Grant);
    } else {
        println!("[prov] provisioning failed");
        let _ = PZ.try_send(BeepEvent::Denied);
        status_led::set_state(status_led::LedState::DeniedOrOffline);
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
            let _ = wifi_controller.disconnect_async().await;
            match wifi_controller.connect_async().await {
                Ok(_) => println!("WiFi connected"),
                Err(e) => {
                    println!("WiFi connection failed: {:?}", e);
                    Timer::after(Duration::from_secs(2)).await;
                    continue;
                }
            }
        }

        // Wait for DHCP (up to 30 s).
        let mut dhcp_ok = false;
        for _ in 0..30 {
            if stack.config_v4().is_some() {
                dhcp_ok = true;
                break;
            }
            Timer::after(Duration::from_secs(1)).await;
        }
        if !dhcp_ok {
            println!("DHCP timeout — retrying...");
            Timer::after(Duration::from_secs(2)).await;
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
                // Connected MQTT pump loop: drain outbound queues then poll with bounded wait.
                loop {
                    // 1. Drain and publish any pending auth requests.
                    while let Ok(auth_payload) = AUTH_OUTBOUND.try_receive() {
                        let pkt = Publication::new(auth_topic.as_str(), auth_payload.as_str());
                        if let Err(e) = session.publish(pkt).await {
                            println!("[mqtt] auth publish error: {:?}", e);
                            break;
                        }
                    }

                    // 2. Drain and publish any claim requests.
                    while let Ok(claim_payload) = PROV_CLAIM_OUTBOUND.try_receive() {
                        println!("[mqtt] sending claim to verifier");
                        let pkt = Publication::new(claim_topic.as_str(), claim_payload.as_str())
                            .qos(minimq::QoS::AtLeastOnce);
                        let _ = session.publish(pkt).await;
                    }

                    // 3. Drain and publish any done reports.
                    while let Ok((job_id, ok, counter, reason)) = PROV_DONE_OUTBOUND.try_receive() {
                        println!("[mqtt] sending done report to verifier");
                        let done = provision_flow::build_done_json(job_id.as_str(), ok, counter, reason);
                        let pkt = Publication::new(done_topic.as_str(), done.as_str())
                            .qos(minimq::QoS::AtLeastOnce);
                        let _ = session.publish(pkt).await;
                    }

                    // 4. Drive MQTT with a bounded 100 ms wait (as documented in minimq examples).
                    match embassy_time::with_timeout(Duration::from_millis(100), session.poll()).await {
                        Ok(Ok(Some(msg))) => {
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
                                let now_ms = Instant::now().as_millis() as u64;
                                if let Ok(text) = core::str::from_utf8(payload) {
                                    let action = {
                                        let mut m = PROV_MACHINE.lock().await;
                                        let was_claim = matches!(m.state, ProvState::ClaimWait(..));
                                        if was_claim {
                                            m.on_claim(text, now_ms)
                                        } else {
                                            m.on_job(text, now_ms, config::PROVISION_WINDOW_SECS).1
                                        }
                                    };
                                    match action {
                                        ProvAction::Arm => {
                                            println!("[prov] job armed — tap blank tag now");
                                            let _ = PZ.try_send(BeepEvent::ProvisionArmed);
                                        }
                                        ProvAction::PublishClaim(claim) => {
                                            let pkt = Publication::new(claim_topic.as_str(), claim.as_str())
                                                .qos(minimq::QoS::AtLeastOnce);
                                            let _ = session.publish(pkt).await;
                                        }
                                        ProvAction::ProvisionStart => {
                                            println!("[prov] keyed claim reply received from verifier");
                                        }
                                        ProvAction::Fail(j_id, reason) => {
                                            println!("[prov] job rejected: {}", reason);
                                            let done = provision_flow::build_done_json(j_id.as_str(), false, 0, reason);
                                            let pkt = Publication::new(done_topic.as_str(), done.as_str())
                                                .qos(minimq::QoS::AtLeastOnce);
                                            let _ = session.publish(pkt).await;
                                            let _ = PZ.try_send(BeepEvent::Denied);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        Ok(Ok(None)) => {
                            // Local progress (PINGRESP / SUBACK / keepalive)
                        }
                        Ok(Err(e)) => {
                            println!("[mqtt] session poll error: {:?}", e);
                            blog!("mqtt poll error: {:?}", e);
                            break;
                        }
                        Err(_) => {
                            // 100 ms timeout with no incoming publish packet: loop to service outbound queues
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
                println!("MQTT session connect failed: {:?}", e);
                status_led::set_state(status_led::LedState::DeniedOrOffline);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
            }
        }
    }
}
