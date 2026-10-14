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
    provision, provision_flow::{ProvAction, ProvMachine, ProvState},
    reader_supervisor::{Action, ResetPolicy},
    relay, status_led, tag_debounce,
};
use crate::piezo::{self, BeepEvent};
use crate::piezo::PIEZO_CHANNEL as PZ;

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
    let mut job_topic = heapless::String::<96>::new();
    let mut claim_topic = heapless::String::<96>::new();
    let mut done_topic = heapless::String::<96>::new();
    let _ = write!(&mut auth_topic, "access/{}/auth", config::DEVICE_ID);
    let _ = write!(&mut cmd_topic, "access/{}/cmd", config::DEVICE_ID);
    let _ = write!(&mut presence_topic, "access/{}/presence", config::DEVICE_ID);

    // Audible connection progress: joining Wi-Fi first.
    piezo::set_conn_state(piezo::conn::WAIT_WIFI);
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

/// Provisioning flow helper macro.
///
/// A macro (not a fn) because every arm needs `&mut session` with minimq's
/// concrete session type — inlining dodges the generic-bounds plumbing while
/// keeping one authoritative implementation of the action semantics.
macro_rules! handle_prov_action {
    ($action:expr, $prov:expr, $session:expr, $claim_topic:expr, $done_topic:expr) => {
        match $action {
            ProvAction::None => {}
            ProvAction::Arm => {
                let _ = PZ.try_send(BeepEvent::ProvisionArmed);
                println!("[prov] job armed — tap a blank NTAG 424 now");
            }
            ProvAction::IgnoreSecond => {
                let _ = PZ.try_send(BeepEvent::Denied);
                println!("[prov] second job ignored (busy)");
            }
            ProvAction::TapRejected => {
                let _ = PZ.try_send(BeepEvent::Denied);
                println!("[prov] tapped uid does not match the job — rejected");
            }
            ProvAction::PublishClaim(claim) => {
                let pkt = Publication::new($claim_topic, claim.as_str())
                    .qos(minimq::QoS::AtLeastOnce);
                match $session.publish(pkt).await {
                    Ok(_) => println!("[prov] claim published — waiting for keyed job"),
                    Err(e) => println!("[prov] claim publish failed: {:?}", e),
                }
            }
            ProvAction::ProvisionStart => {
                println!("[prov] provisioning starting");
            }
            ProvAction::CompleteOk(job_id, counter) => {
                let done = crate::provision_flow::build_done_json(job_id.as_str(), true, counter, "");
                let pkt =
                    Publication::new($done_topic, done.as_str()).qos(minimq::QoS::AtLeastOnce);
                if let Err(e) = $session.publish(pkt).await {
                    println!("[prov] done publish failed: {:?}", e);
                }
                let _ = PZ.try_send(BeepEvent::ProvisionOk);
                println!("[prov] SUCCESS (counter {})", counter);
            }
            ProvAction::Fail(job_id, reason) => {
                let done = crate::provision_flow::build_done_json(job_id.as_str(), false, 0, reason);
                let pkt =
                    Publication::new($done_topic, done.as_str()).qos(minimq::QoS::AtLeastOnce);
                if let Err(e) = $session.publish(pkt).await {
                    println!("[prov] done publish failed: {:?}", e);
                }
                let _ = PZ.try_send(BeepEvent::ProvisionFail);
                println!("[prov] FAILED: {}", reason);
            }
            ProvAction::LapseSilent => {
                println!("[prov] job window lapsed — going idle");
            }
        }
    };
}

/// Decode 32 ASCII hex chars into a 16-byte key.
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
    for i in 0..16 {
        let (hi, lo) = match (nib(b[2 * i]), nib(b[2 * i + 1])) {
            (Some(h), Some(l)) => (h, l),
            _ => return false,
        };
        out[i] = (hi << 4) | lo;
    }
    true
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

        // Wi-Fi + DHCP up; now audible progress moves to MQTT joining.
        piezo::set_conn_state(piezo::conn::WAIT_MQTT);

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

                // Provisioning state machine (one instance per MQTT session;
                // a reconnect drops any in-flight job — the server TTL lapses).
                let mut prov = ProvMachine::new();

                // Fully online — confirmation melody via the conn-state hook.
                piezo::set_conn_state(piezo::conn::ONLINE);

                // Subscribe to commands AND provisioning jobs. Two separate
                // SUBSCRIBEs: minimq 0.12's multi-filter SUBSCRIBE encoding is
                // untested upstream (only the single-filter path has a wire
                // test) and EMQX rejects the combined packet with
                // topic_filter_invalid, killing the session on every connect.
                let cmd_filters = [TopicFilter::new(cmd_topic.as_str())];
                if let Err(e) = session.subscribe(&cmd_filters, &[]).await {
                    println!("subscribe failed: {:?}", e);
                    status_led::set_state(status_led::LedState::DeniedOrOffline);
                    Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
                    continue;
                }
                let job_filters = [TopicFilter::new(job_topic.as_str())];
                if let Err(e) = session.subscribe(&job_filters, &[]).await {
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
                        Ok(Ok(Some(msg))) => {
                            let topic = msg.topic();
                            let payload = msg.payload();
                            if topic == cmd_topic.as_str() {
                                match cmd::parse_cmd_slice(payload) {
                                    Ok(c) => {
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
                                    Err(e) => println!("cmd parse error: {:?}", e),
                                }
                            } else if topic == job_topic.as_str() {
                                // Job payloads: new arming (Idle only) or the
                                // keyed claim reply (ClaimWait only).
                                let now_ms = Instant::now().as_millis() as u64;
                                match core::str::from_utf8(payload) {
                                    Ok(text) => {
                                        let was_claim = matches!(prov.state, ProvState::ClaimWait(..));
                                        let (_, action) = if was_claim {
                                            (None, prov.on_claim(text, now_ms))
                                        } else {
                                            prov.on_job(text, now_ms, config::PROVISION_WINDOW_SECS)
                                        };
                                        handle_prov_action!(
                                            action, &mut prov, &mut session,
                                            claim_topic.as_str(), done_topic.as_str()
                                        );
                                    }
                                    Err(_) => println!("[prov] job payload not UTF-8"),
                                }
                            }
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(e)) => {
                            println!("MQTT poll error: {:?}", e);
                            break;
                        }
                        Err(_) => {} // No inbound packet within the window.
                    }

                    // Provisioning deadlines tick with the loop cadence
                    // (~50 ms): arm-window lapse is silent, claim wait fails.
                    let now_ms = Instant::now().as_millis() as u64;
                    {
                        let tick_action = prov.on_tick(now_ms);
                        handle_prov_action!(
                            tick_action, &mut prov, &mut session,
                            claim_topic.as_str(), done_topic.as_str()
                        );
                    }

                    // Poll NFC and run the edge-triggered debounce state machine.
                    if let Some(ref mut pn) = pn532 {
                        no_nfc_logged = false;
                        let now = Instant::now();
                        let now_ms = now.as_millis() as u64;

                        // Periodic liveness probe (every 64 iterations, ~30 s):
                        // a real GetFirmwareVersion round-trip. Catches the
                        // fake-ready wedge (STATUS says ready, RF core dead,
                        // every scan returns clean NbTg=0) that never produces
                        // poll errors for the supervisor to count.
                        {
                            use core::sync::atomic::{AtomicU32, Ordering};
                            static HEALTH_N: AtomicU32 = AtomicU32::new(0);
                            let it = HEALTH_N.fetch_add(1, Ordering::Relaxed);
                            if it % 64 == 0 {
                                match nfc::health_check(pn) {
                                    Ok(fw) => {
                                        if it % 640 == 0 {
                                            println!(
                                                "[nfc] health ok fw={:02x}:{:02x}:{:02x}:{:02x} (iter {})",
                                                fw[0], fw[1], fw[2], fw[3], it
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        println!(
                                            "[nfc] health check FAILED ({:?}) — pulsing RSTO + reinit",
                                            e
                                        );
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
                        }

                        match nfc::poll_tag(pn) {
                            Ok(tag_opt) => {
                                policy.observe(false, now_ms);

                                let obs = tag_opt
                                    .as_ref()
                                    .map(tag_debounce::TagObservation::from_tag_info);

                                if let Some(ev) = debounce.observe(now, obs) {
                                    // Single tap path: only debounce-confirmed
                                    // sightings beep/provision/auth.
                                    let _ = PZ.try_send(BeepEvent::TagDetected);

                                    // SAK 0x20 => ISO 14443-4 (DESFire / NTAG 424 DNA).
                                    if ev.sak == 0x20 {
                                        status_led::set_state(status_led::LedState::TagReading);

                                        // Provisioning branch: an armed job
                                        // consumes the tap instead of the
                                        // auth path.
                                        if !prov.state.is_idle() {
                                            if let Some(tag) = tag_opt.as_ref() {
                                                let action = prov.on_tap(
                                                    tag.uid,
                                                    now_ms,
                                                    config::CLAIM_WAIT_SECS,
                                                );
                                                handle_prov_action!(
                                                    action, &mut prov, &mut session,
                                                    claim_topic.as_str(),
                                                    done_topic.as_str()
                                                );
                                            }
                                        } else {

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
                                                // ISO-7816 status-word hints from the
                                                // bench session (docs/PN532-SPI-NOTES.md).
                                                let hint = match &e {
                                                    ntag424::NdefError::Status(0x6A, 0x82) => {
                                                        " — NDEF file not found: tag is BLANK/unprovisioned (expected on unwritten NTAG 424s)"
                                                    }
                                                    ntag424::NdefError::Status(0x69, 0x82) => {
                                                        " — security status not satisfied: tag requires authentication first"
                                                    }
                                                    ntag424::NdefError::Status(0x6A, 0x86) => {
                                                        " — APDU parameters wrong (protocol mismatch)"
                                                    }
                                                    _ => "",
                                                };
                                                println!("NDEF read error: {:?}{}", e, hint);
                                                status_led::set_state(
                                                    status_led::LedState::DeniedOrOffline,
                                                );
                                            }
                                            } // else: provisioning branch consumed the tap
                                        }
                                    }
                                }

                                // Provisioning execution: a dedicated busy
                                // window. provision_tag runs to completion
                                // (~2-8 s, one APDU exchange per RF round) —
                                // comfortably under the 30 s MQTT keepalive,
                                // so no step-splitting is needed. Auth
                                // publishes are impossible during this window
                                // because the machine leaves Provisioning
                                // before returning to the auth path.
                                if let Some((job_id, key_hex)) = prov.pending_context() {
                                    status_led::set_state(status_led::LedState::TagReading);
                                    println!("[prov] provisioning tag (job {})…", job_id);

                                    let mut rnda = [0u8; 16];
                                    let mut rng = esp_hal::rng::Rng::new();
                                    for chunk in rnda.chunks_mut(4) {
                                        let w = rng.random().to_le_bytes();
                                        chunk.copy_from_slice(&w[..chunk.len()]);
                                    }
                                    let mut key = [0u8; 16];
                                    let run = if decode_key16(key_hex.as_str(), &mut key) {
                                        let mut report =
                                            provision::ProvisionReport { uid: [0; 7], counter: 0 };
                                        let pn_ref: &mut _ = &mut *pn;
                                        let mut exchange =
                                            move |apdu: &[u8], out: &mut [u8]| -> Result<
                                                usize,
                                                ntag424::NdefError,
                                            > {
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
                                            println!("[prov] sequence error: {:?}", e);
                                            (false, 0, "provision error")
                                        }
                                    };
                                    let action = prov.on_provision_done(ok, counter, reason);
                                    handle_prov_action!(
                                        action, &mut prov, &mut session,
                                        claim_topic.as_str(), done_topic.as_str()
                                    );
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

                    // Clock telemetry: every 1024 iterations, print the
                    // embassy clock reading. With a healthy 30 ms cadence the
                    // value should advance ~30 000 ms per print; a cycle-count
                    // masquerading as ms advances millions.
                    {
                        use core::sync::atomic::{AtomicU32, Ordering};
                        static ITER: AtomicU32 = AtomicU32::new(0);
                        let it = ITER.fetch_add(1, Ordering::Relaxed);
                        if it % 1024 == 0 {
                            println!(
                                "[probe] loop tick iter={} now_ms={}",
                                it,
                                Instant::now().as_millis()
                            );
                        }
                    }
                }

                // Session died mid-loop (the tag loop only exits via break on
                // transport/protocol failure). Honor the reconnect backoff
                // here — without it a flapping broker pins the CPU at
                // reconnect rate and starves every other task. Audible state
                // drops to the slow reconnect beep.
                piezo::set_conn_state(piezo::conn::RECONNECT);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
            }
            Err(e) => {
                println!("MQTT session connect failed: {:?}", e);
                status_led::set_state(status_led::LedState::DeniedOrOffline);
                Timer::after(Duration::from_secs(next_backoff(&mut backoff_secs))).await;
            }
        }
    }
}

