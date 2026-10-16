#!/usr/bin/env bash
# arm-provision.sh — one-shot OTA tag provisioning drill.
#
# Waits until the door node holds a STABLE broker session with BOTH
# subscriptions live (the wildcard job is non-retained: arming before the
# node is subscribed silently drops the job), then arms a provisioning job
# and gates the tap on a Zenity dialog.
#
# Usage:
#   export ADMIN_BEARER_TOKEN=...      # verifier admin token (required)
#   export VERIFYER_URL=...            # optional, default http://10.7.1.25:8001
#   export BROKER_HOST=...             # optional, default 10.7.1.106
#   export BROKER_SSH=root@10.7.1.106  # optional; SSH for `emqx ctl` polling
#   ./scripts/arm-provision.sh [member_key] [device_id] [ttl_secs]
#
# Defaults: member_key=testmember1 device_id=keygate1 ttl_secs=120
set -uo pipefail

export PATH="$HOME/.guix-profile/bin:$PATH"
export DISPLAY="${DISPLAY:-:0}"

MEMBER="${1:-testmember1}"
DEVICE="${2:-keygate1}"
TTL="${3:-120}"
VERIFYER_URL="${VERIFYER_URL:-http://10.7.1.25:8001}"
export BROKER_HOST="${BROKER_HOST:-10.7.1.106}"
BROKER_SSH="${BROKER_SSH:-root@10.7.1.106}"

: "${ADMIN_BEARER_TOKEN:?export ADMIN_BEARER_TOKEN (verifier admin token)}"

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }

# ---------------------------------------------------------------------------
# 1. Wait for a stable, fully-subscribed node session.
#    Reads broker ground truth via `emqx ctl clients list` over SSH.
# ---------------------------------------------------------------------------
node_state() {
    timeout 15 ssh -o BatchMode=yes -o ConnectTimeout=8 \
        -o StrictHostKeyChecking=no "$BROKER_SSH" \
        "emqx ctl clients list 2>/dev/null | grep -E '^Client\\(($DEVICE|keygate),'" 2>/dev/null
}

STABLE=0
for i in $(seq 1 40); do
    LINE=$(node_state)
    if [ -z "$LINE" ]; then
        log "[$i] node not connected (no broker session)"
    else
        CONN=$(printf '%s' "$LINE" | grep -oE 'connected=(true|false)' | head -1)
        SUBS=$(printf '%s' "$LINE" | grep -oE 'subscriptions=[0-9]+' | head -1)
        SUBS_N=$(printf '%s' "$SUBS" | cut -d= -f2)
        log "[$i] $CONN $SUBS"
        if [ "$CONN" = "connected=true" ] && [ "${SUBS_N:-0}" -ge 2 ]; then
            log "session up + subscribed — soaking 12 s to confirm stability"
            sleep 12
            LINE2=$(node_state)
            SUBS_N2=$(printf '%s' "$LINE2" | grep -oE 'subscriptions=[0-9]+' | cut -d= -f2)
            if printf '%s' "$LINE2" | grep -q 'connected=true' && \
               [ "${SUBS_N2:-0}" -ge 2 ]; then
                STABLE=1
                log "STABLE ✓"
                break
            fi
            log "flapped during soak — rewaiting"
        fi
    fi
    sleep 8
done

if [ "$STABLE" != 1 ]; then
    log "FAILED: node never reached a stable subscribed session"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Broker monitor (background, 160 s) — writer + access topics.
# ---------------------------------------------------------------------------
python3 - <<'EOF' > /tmp/armprov-mqtt.log 2>&1 &
import socket, struct, time, os
def mstr(s): b=s.encode(); return struct.pack(">H",len(b))+b
def rem(n):
    o=b""
    while True:
        b=n%128; n//=128
        if n: o+=bytes([b|128])
        else: o+=bytes([b]); break
    return o
def readpkt(s):
    h=s.recv(1)
    if not h: return None,None
    rl=0; mult=1
    for _ in range(4):
        b=s.recv(1)[0]; rl+=(b&127)*mult; mult*=128
        if not b&128: break
    body=b""
    while len(body)<rl: body+=s.recv(rl-len(body))
    return h[0],body
vh = mstr("MQTT")+bytes([4,0x02])+struct.pack(">H",170)+mstr("armprov-%d"%time.time())
s=socket.create_connection((os.environ["BROKER_HOST"],1883),timeout=6)
s.sendall(bytes([0x10])+rem(len(vh))+vh)
readpkt(s)
sub=struct.pack(">H",1)+mstr("access/#")+bytes([1])+mstr("writer/#")+bytes([1])
s.sendall(bytes([0x82])+rem(len(sub))+sub)
readpkt(s)
t0=time.time(); last_ping=time.time()
s.settimeout(1.0)
while time.time()-t0<160:
    try:
        t,body=readpkt(s)
        if t is None: break
        if t&0xF0==0x30:
            tl=struct.unpack(">H",body[0:2])[0]
            topic=body[2:2+tl].decode(errors="replace"); off=2+tl
            if body[1]&0x06: off+=2
            pl=body[off:][:160].decode(errors="replace")
            if topic.endswith("presence"): pl=pl[-10:]
            print(time.strftime("%H:%M:%S"),topic,"->",pl,flush=True)
        if time.time()-last_ping>25:
            s.sendall(bytes([0xC0,0])); last_ping=time.time()
    except socket.timeout:
        if time.time()-last_ping>25:
            try: s.sendall(bytes([0xC0,0])); last_ping=time.time()
            except Exception: break
EOF
MON=$!

# ---------------------------------------------------------------------------
# 3. Arm.
# ---------------------------------------------------------------------------
sleep 1
# Serial capture (background) — must start BEFORE arming so the
# "[prov] job armed" print and claim traffic are not lost.
PORT=$(ls /dev/ttyUSB* 2>/dev/null | head -1)
CAT=""
if [ -n "$PORT" ]; then
    stty -F "$PORT" 115200 cs8 -cstopb -parenb raw -echo 2>/dev/null
    : > /tmp/armprov-serial.log
    timeout 160 cat "$PORT" > /tmp/armprov-serial.log 2>/dev/null &
    CAT=$!
fi

log "ARM: member=$MEMBER device=$DEVICE ttl=$TTL"
RESP=$(curl -s -m 8 -X POST "$VERIFYER_URL/admin/api/jobs" \
    -H "Authorization: Bearer $ADMIN_BEARER_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"member_key\":\"$MEMBER\",\"device_id\":\"$DEVICE\",\"ttl_secs\":$TTL}")
log "verifier: $RESP"
printf '%s' "$RESP" | grep -q job_id || { log "ARM FAILED"; kill $MON 2>/dev/null; exit 1; }

# ---------------------------------------------------------------------------
# 4. Tap gate.
# ---------------------------------------------------------------------------

zenity --question --timeout=110 \
    --title="arm-provision: TAP" \
    --text="Listen for <b>3 chirps</b> = armed.\n\nThen <b>TAP the blank tag</b> and <b>KEEP IT ON the reader</b>\nuntil the beeping pattern finishes (~15 s)" \
    2>/dev/null || log "(tap gate closed)"

sleep 30
[ -n "$CAT" ] && kill $CAT 2>/dev/null
kill $MON 2>/dev/null

# ---------------------------------------------------------------------------
# 5. Report.
# ---------------------------------------------------------------------------
echo "=== broker events ==="
head -15 /tmp/armprov-mqtt.log
if [ -n "$CAT" ]; then
    echo "=== serial: provision/beeps/auth ==="
    grep -aoE "\[prov\][^\"]*|\[piezo\] play [A-Za-z]+|auth: [^\"]*|GRANT[^\"]*|DENY[^\"]*|SUCCESS[^\"]*" \
        /tmp/armprov-serial.log | sort | uniq -c | sort -rn | head -12
fi
echo "=== done ==="
