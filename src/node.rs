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
use crate::ota;
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

/// Millis-since-boot at the last physical tag detection: t0 for the
/// tap→verdict latency measurement printed on every GRANT/DENY. u32 wraps at
/// ~49 days — harmless for a delta measured within seconds of a tap.
pub static TAP_T0_MS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn uptime_ms() -> u32 {
    embassy_time::Instant::now().as_millis() as u32
}

/// Main node entry point running both decoupled runners concurrently.
pub async fn run<I: pn532::Interface>(
    pn532: Option<Pn532<I, Pn532Delay, 300>>,
    reader_reset: Option<esp_hal::gpio::Output<'static>>,
    stack: embassy_net::Stack<'static>,
    wifi_controller: esp_radio::wifi::WifiController<'static>,
    wdt: esp_hal::timer::timg::Wdt<esp_hal::peripherals::TIMG1<'static>>,
) -> ! {
    embassy_futures::join::join(
        nfc_runner(pn532, reader_reset),
        mqtt_runner(stack, wifi_controller, wdt),
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
    let mut nfc_down_ticks: u32 = 0;
    let mut is_dna_active = false;
    let mut last_dna_tag: Option<nfc::TagInfo> = None;

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
                        let _ = nfc::soft_reinit(pn, 2500);
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
                continue;
            } else if is_claim_wait {
                // Keep target 1 intact while verifier computes diversified key!
                // No polling in this state: clear the field UID so the melody
                // cannot outlive the tap that armed the window.
                piezo::set_field_uid(&[]).await;
                Timer::after(Duration::from_millis(15)).await;
                continue;
            }

            // Poll for tags or check presence of resting ISO-DEP target:
            // For DNA tags in ISO-DEP mode, re-polling fails because Target 1 is active.
            // is_target_present pings Target 1 with a 4-byte frame in <10ms, detecting
            // resting presence seamlessly and physical removal instantly.
            let tag_opt = if is_dna_active {
                if nfc::is_target_present(pn, 1) {
                    last_dna_tag.clone()
                } else {
                    is_dna_active = false;
                    last_dna_tag = None;
                    nfc::release_target(pn, 0);
                    None
                }
            } else {
                let opt = nfc::poll_tag(pn);
                if let Some(ref tag) = opt {
                    if tag.sak == 0x20 {
                        is_dna_active = true;
                        last_dna_tag = Some(tag.clone());
                    }
                }
                opt
            };
            let obs = tag_opt.as_ref().map(tag_debounce::TagObservation::from_tag_info);

            // Update debounce state machine FIRST, so presence tracking
            // filters out PN532 RF polling flicker while a tag rests on the reader.
            let tap_event = debounce.observe(now, obs);

            // In-field identity melody: driven by the debounced presence state.
            // Raw `poll_tag` flickers to None when an activated tag is already
            // in target slot 1; `debounce.state()` holds `Tapped` continuously
            // as long as the card is on the reader, and only transitions to
            // `Idle` when the tag is physically removed.
            match debounce.state() {
                tag_debounce::State::Tapped { uid, uid_len } => {
                    piezo::set_field_uid(&uid[..uid_len as usize]).await;
                }
                tag_debounce::State::Removing {
                    last_uid,
                    last_uid_len,
                    ..
                } => {
                    piezo::set_field_uid(&last_uid[..last_uid_len as usize]).await;
                }
                tag_debounce::State::Idle => {
                    piezo::set_field_uid(&[]).await;
                }
            }

            if let Some(ev) = tap_event {
                // Audible feedback: immediate wake on every physical tag detection.
                let _ = PZ.try_send(BeepEvent::TagDetected);
                TAP_T0_MS.store(uptime_ms(), core::sync::atomic::Ordering::Relaxed);

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
                                is_dna_active = false;
                                last_dna_tag = None;
                                nfc::release_target(pn, 0);
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
                                    Ok(n) => {
                                        println!(
                                            "[latency] ndef read done +{} ms",
                                            uptime_ms().saturating_sub(
                                                TAP_T0_MS.load(core::sync::atomic::Ordering::Relaxed)
                                            )
                                        );
                                        match ntag424::extract_ndef_uri(&ndef_buf[..n]) {
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
                                    }
                                    }
                                    Err(e) => {
                                        // Blank / unwritten tag — perfectly normal.
                                        println!("NDEF read: unwritten/blank tag ({:?})", e);
                                        status_led::set_state(status_led::LedState::MqttConnected);
                                    }
                                }
                            }
                        }
                    }
                }
        } else {
            if !no_nfc_logged {
                println!("[nfc] no reader initialized — idling NFC polling");
                blog!("pn532 absent — reader down alarm active");
                no_nfc_logged = true;
                nfc_down_ticks = 0;
            }
            // Persistent failure tone: the node must not sit silent when it
            // is not guarding the door. One NfcDown pattern every ~15 s.
            nfc_down_ticks += 1;
            if nfc_down_ticks % 15 == 0 {
                let _ = PZ.try_send(BeepEvent::NfcDown);
            }
            Timer::after(Duration::from_secs(1)).await;
        }

        // Cooperative yield to executor tasks (matches xiao-c6 adaptive yield).
        Timer::after(Duration::from_millis(150)).await;
    }
}

/// Helper to execute the cryptographic provisioning sequence on the tapped tag.
async fn execute_tag_provisioning<I: pn532::Interface>(
    pn: &mut Pn532<I, Pn532Delay, 300>,
    job_id: &str,
    key_hex: &str,
) {
    println!("[prov] provisioning tag (job {})...", job_id);
    // The write-progress tone (conn::PROV_WRITING) owns the sound here; the
    // identity melody must not fight it (the tag obviously stays in field).
    piezo::set_field_uid(&[]).await;
    piezo::set_conn_state(piezo::conn::PROV_WRITING);
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
            println!("[apdu-tx] (len {}) {:02x?}", apdu.len(), apdu);
            let resp = nfc::in_data_exchange(pn, 1, apdu)
                .map_err(|e| {
                    println!("[exchange] in_data_exchange error: {:?}", e);
                    ntag424::NdefError::Transport
                })?;
            println!("[apdu-rx] (len {}) {:02x?}", resp.len(), resp);
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
            let reason = match e {
                provision::ProvisionError::KeyMismatch => "key-mismatch",
                _ => "provision error",
            };
            (false, 0, reason)
        }
    };

    let _action = {
        let mut m = PROV_MACHINE.lock().await;
        m.on_provision_done(ok, counter, reason)
    };

    let mut j_id = heapless::String::<32>::new();
    let _ = j_id.push_str(job_id);
    let _ = PROV_DONE_OUTBOUND.try_send((j_id, ok, counter, reason));

    piezo::set_conn_state(piezo::conn::ONLINE);

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
    mut wdt: esp_hal::timer::timg::Wdt<esp_hal::peripherals::TIMG1<'static>>,
) -> ! {
    static TCP_RX: static_cell::StaticCell<[u8; 1024]> = static_cell::StaticCell::new();
    static TCP_TX: static_cell::StaticCell<[u8; 1024]> = static_cell::StaticCell::new();
    static MQTT_RX: static_cell::StaticCell<[u8; 1024]> = static_cell::StaticCell::new();
    static MQTT_TX: static_cell::StaticCell<[u8; 1024]> = static_cell::StaticCell::new();

    let tcp_rx_buf = TCP_RX.init([0u8; 1024]);
    let tcp_tx_buf = TCP_TX.init([0u8; 1024]);
    let mqtt_rx_buf = MQTT_RX.init([0u8; 1024]);
    let mqtt_tx_buf = MQTT_TX.init([0u8; 1024]);

    let mut auth_topic = heapless::String::<96>::new();
    let mut cmd_topic = heapless::String::<96>::new();
    let mut log_topic = heapless::String::<96>::new();
    let mut presence_topic = heapless::String::<96>::new();
    let mut job_topic = heapless::String::<96>::new();
    let mut claim_topic = heapless::String::<96>::new();
    let mut done_topic = heapless::String::<96>::new();
    let mut ota_meta_topic = heapless::String::<96>::new();
    let mut ota_data_topic = heapless::String::<96>::new();
    let mut ota_end_topic = heapless::String::<96>::new();
    let mut ota_status_topic = heapless::String::<96>::new();

    let _ = write!(&mut auth_topic, "access/{}/auth", config::DEVICE_ID);
    let _ = write!(&mut cmd_topic, "access/{}/cmd", config::DEVICE_ID);
    let _ = write!(&mut presence_topic, "access/{}/presence", config::DEVICE_ID);
    let _ = write!(&mut log_topic, "access/{}/log", config::DEVICE_ID);
    let _ = write!(&mut job_topic, "writer/{}/job", config::DEVICE_ID);
    let _ = write!(&mut claim_topic, "writer/{}/claim", config::DEVICE_ID);
    let _ = write!(&mut done_topic, "writer/{}/done", config::DEVICE_ID);
    let _ = write!(&mut ota_meta_topic, "access/{}/ota/meta", config::DEVICE_ID);
    let _ = write!(&mut ota_data_topic, "access/{}/ota/data", config::DEVICE_ID);
    let _ = write!(&mut ota_end_topic, "access/{}/ota/end", config::DEVICE_ID);
    let _ = write!(&mut ota_status_topic, "access/{}/ota/status", config::DEVICE_ID);

    let broker_port: u16 = config::MQTT_PORT.parse().unwrap_or(1883);
    let mut backoff_secs: u64 = 1;
    let mut cycle: u32 = 0;

    // Pick the STRONGEST AP for our SSID and pin the association to it.
    //
    // The fleet SSID is broadcast by many BSSIDs with ~50 dB of spread (bench
    // survey: two APs at ≈-40 dBm across the room, distant cisco units at
    // -70..-90). Without pinning, association landed on a -86 dBm distant AP
    // while two -40 dBm APs sat next to the bench — every packet-starved
    // keepalive kick and boot marathon followed from that.
    match wifi_controller
        .scan_async(&esp_radio::wifi::scan::ScanConfig::default())
        .await
    {
        Ok(aps) => {
            let best = aps
                .iter()
                .filter(|ap| ap.ssid.as_str() == config::WIFI_SSID)
                .max_by_key(|ap| ap.signal_strength);
            match best {
                Some(ap) => {
                    println!(
                        "wifi: best {} AP {:02x?} ch {} rssi {} dBm (of {} scanned)",
                        ap.ssid.as_str(),
                        ap.bssid,
                        ap.channel,
                        ap.signal_strength,
                        aps.len()
                    );
                    blog!(
                        "wifi: best AP rssi {} dBm (of {} scanned)",
                        ap.signal_strength,
                        aps.len()
                    );
                    let station_config = esp_radio::wifi::Config::Station(
                        esp_radio::wifi::sta::StationConfig::default()
                            .with_ssid(config::WIFI_SSID)
                            .with_password(config::WIFI_PASS.into())
                            .with_bssid(ap.bssid)
                            .with_auth_method(
                                ap.auth_method
                                    .unwrap_or(esp_radio::wifi::AuthenticationMethod::Wpa2Personal),
                            ),
                    );
                    wifi_controller.set_config(&station_config).unwrap();
                }
                None => {
                    println!(
                        "wifi: scan found no '{}' AP — keeping default config",
                        config::WIFI_SSID
                    );
                }
            }
        }
        Err(e) => {
            println!("wifi: scan failed ({:?}) — keeping default config", e);
        }
    }

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
        cycle += 1;
        // HARD rate floor: this loop may never cycle faster than 1 Hz. A hot
        // loop here floods the broker with CONNECT takeovers (runq_overload),
        // spams the UART at line rate, and masks the real failure cadence.
        // Every retry path funnels back through here; no exceptions.
        Timer::after(Duration::from_secs(1)).await;
        println!("[mqtt-cycle {}]", cycle);

        // Audible connection progress: joining Wi-Fi first.
        piezo::set_conn_state(piezo::conn::WAIT_WIFI);
        status_led::set_state(status_led::LedState::WifiConnecting);

        if !wifi_controller.is_connected() {
            println!("Connecting to WiFi...");
            match wifi_controller.connect_async().await {
                Ok(_) => println!("WiFi connected"),
                Err(e) => {
                    println!("WiFi connection failed: {:?}", e);
                    blog!("wifi assoc failed: {:?}", e);
                    Timer::after(Duration::from_secs(5)).await;
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

        // Open TCP transport, then the MQTT session — both bounded. A broker
        // that accepts TCP but stalls CONNACK must not hold a zombie session
        // (and our pump hostage) for minutes.
        let mut socket = TcpSocket::new(stack, &mut tcp_rx_buf[..], &mut tcp_tx_buf[..]);
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

        let mqtt_config = match ConfigBuilder::new(Buffers::new(&mut mqtt_rx_buf[..], &mut mqtt_tx_buf[..]))
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

        match embassy_time::with_timeout(Duration::from_secs(10), session.connect(socket)).await {
            Ok(Ok(ConnectEvent::Connected)) | Ok(Ok(ConnectEvent::Reconnected)) => {
                println!("MQTT connected! Broker online.");
                status_led::set_state(status_led::LedState::MqttConnected);
                backoff_secs = 1;

                // Flush buffered diagnostics (bounded — boot milestones +
                // recent events; the ring holds 64, drain the overflow).
                let mut flushed = 0u8;
                while flushed < 12 {
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
                if let Err(e) = session.publish(online).await {
                    println!("[mqtt] presence publish failed: {:?}", e);
                }

                // Subscribe to command, provisioning and OTA topics (one
                // SUBSCRIBE carries them all).
                // OTA topics at QoS1: image chunks must not be dropped (the
                // 1KB rx buffer cannot absorb a line-rate chunk burst).
                let qos1 = minimq::SubscriptionOptions::default()
                    .maximum_qos(minimq::QoS::AtLeastOnce);
                let filters = [
                    TopicFilter::new(cmd_topic.as_str()),
                    TopicFilter::new(job_topic.as_str()),
                    TopicFilter::new(ota_meta_topic.as_str()).options(qos1),
                    TopicFilter::new(ota_data_topic.as_str()).options(qos1),
                    TopicFilter::new(ota_end_topic.as_str()).options(qos1),
                ];
                if let Err(e) = session.subscribe(&filters, &[]).await {
                    println!("[mqtt] subscribe failed: {:?}", e);
                    status_led::set_state(status_led::LedState::DeniedOrOffline);
                    Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                    continue;
                }

                println!("[mqtt] all subscriptions live — node fully online!");
                blog!("subscriptions live — online");
                // Audible confirmation: online (plays only when truly online & subscribed!).
                piezo::set_conn_state(piezo::conn::ONLINE);

                // Inner connected MQTT pump loop driven by select4.
                // Connected MQTT pump loop: drain outbound queues then poll with bounded wait.
                let mut pump_iters: u32 = 0;
                let mut last_hb_ms = uptime_ms();
                loop {
                    pump_iters += 1;
                    let now_ms = uptime_ms();
                    if now_ms.saturating_sub(last_hb_ms) >= 30_000 {
                        println!("[pump hb {} iters]", pump_iters);
                        last_hb_ms = now_ms;
                    }
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
                    // Watchdog: if ANY task wedges (e.g. a flash op), the
                    // 30s WDT reboots and the OLD build keeps guarding.
                    wdt.feed();
                    // OTA: advance the batched erase; drain status messages.
                    ota::erase_tick().await;
                    while let Ok(status) = crate::ota::STATUS_OUTBOUND.try_receive() {
                        let pkt = minimq::Publication::new(ota_status_topic.as_str(), status.as_str())
                            .qos(minimq::QoS::AtLeastOnce);
                        if let Err(e) = session.publish(pkt).await {
                            println!("[mqtt] ota status publish failed: {:?}", e);
                            break;
                        }
                    }

                    match embassy_time::with_timeout(Duration::from_millis(100), session.poll()).await {
                        Ok(Ok(Some(msg))) => {
                            let topic = msg.topic();
                            let payload = msg.payload();
                            println!("[mqtt] rx {} ({}B)", topic, payload.len());

                            if topic == ota_meta_topic.as_str() {
                                ota::on_meta(payload).await;
                            } else if topic == ota_data_topic.as_str() {
                                ota::on_data(payload).await;
                            } else if topic == ota_end_topic.as_str() {
                                ota::on_end().await;
                            } else if topic == cmd_topic.as_str() {
                                if let Ok(c) = cmd::parse_cmd_slice(payload) {
                                    if c.grant {
                                        // Door timing is LOCAL policy — the
                                        // verifier says accept/deny, nothing more.
                                        let _ =
                                            relay::RELAY_CHANNEL.try_send(config::RELAY_HOLD_MS);
                                        let _ = PZ.try_send(BeepEvent::Granted);
                                        status_led::set_state(status_led::LedState::Grant);
                                        let dt = uptime_ms().saturating_sub(TAP_T0_MS.load(core::sync::atomic::Ordering::Relaxed));
                                        println!(
                                            "GRANT (hold {} ms, +{} ms since tap): {}",
                                            config::RELAY_HOLD_MS,
                                            dt,
                                            c.reason
                                        );
                                    } else {
                                        let _ = PZ.try_send(BeepEvent::Denied);
                                        status_led::set_state(status_led::LedState::DeniedOrOffline);
                                        let dt = uptime_ms().saturating_sub(TAP_T0_MS.load(core::sync::atomic::Ordering::Relaxed));
                                        println!("DENY (+{} ms since tap): {}", dt, c.reason);
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
                                            piezo::set_conn_state(piezo::conn::PROV_ARMED);
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
                                            piezo::set_conn_state(piezo::conn::ONLINE);
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
                            // Cooperative yield so other executor tasks (Wi-Fi, NFC, timers) run cleanly
                            Timer::after(Duration::from_millis(15)).await;
                        }
                        Ok(Err(e)) => {
                            println!("[mqtt] session poll error: {:?}", e);
                            blog!("mqtt poll error: {:?}", e);
                            // Back off before reconnecting: a flapping link
                            // otherwise hot-cycles TCP+MQTT setup at line
                            // rate and hammers the broker.
                            Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
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
            Ok(Err(e)) => {
                println!("MQTT session connect failed: {:?}", e);
                status_led::set_state(status_led::LedState::DeniedOrOffline);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
            }
            Err(_) => {
                println!("[mqtt] connect timeout — no CONNACK in 10s");
                blog!("mqtt connect timeout (10s)");
                status_led::set_state(status_led::LedState::DeniedOrOffline);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
            }
        }
    }
}
