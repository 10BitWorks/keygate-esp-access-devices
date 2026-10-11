#!/usr/bin/env bash
# F3 live drill — one-click verification of the full door access chain:
#   door node online -> tag tap (SUN tuple) -> verifier decision -> grant.
#
# Prerequisites:
#   - The NTAG 424 tag is SUN-provisioned with its per-tag diversified key
#     (derived from the verifier MASTER_KEY; tag enrolled via the verifier
#     admin API first). The key is read from $F3_TAG_KEY or the local file
#     below — it is NOT hardcoded here (public repo).
#   - Door node flashed with a working build (soft-SPI + 3 s timeouts).
#
# Monitor topics (specific filters only — EMQX's default ACL denies exact-`#`):
#   access/<id>/presence  -> door node came online
#   access/<id>/auth      -> tap produced a SUN tuple (tag provisioning works)
#   access/<id>/cmd       -> verifier decision (grant = relay should pulse)
#
# Exit status: 0 = grant received, 1 = window elapsed without grant,
#             2 = broker unreachable.
set -u
export DISPLAY="${DISPLAY:-:0}"

BROKER="${EMQX_BROKER:-10.7.1.106}"
READER="${DOOR_DEVICE_ID:-keygate1}"
WINDOW_SECS="${DRILL_WINDOW:-600}"
LOG="${DRILL_LOG:-/tmp/f3-drill.log}"
TAG_UID="${F3_TAG_UID:-04:87:53:62:1E:18:90}"
TAG_KEY="${F3_TAG_KEY:-$(cat /tmp/opencode/tagkey.txt 2>/dev/null || echo '<set F3_TAG_KEY or /tmp/opencode/tagkey.txt>')}"

if ! zenity --question --title="KeyGate F3 live drill" --text="Before clicking OK:

1. Provision the NTAG 424 tag (UID ${TAG_UID}):
   SUN key: ${TAG_KEY}
   Mirror the UID (14 hex), the counter (decimal, query param 'c'),
   and the CMAC (32 hex) as URL query parameters.
2. Power the door node (USB).
3. Tap the tag FLAT on the reader and HOLD about 5 s.
   The first tap may DENY once (counter starts at 0) — keep holding.

Click OK to start a ${WINDOW_SECS}s monitor on ${BROKER}." 2>/dev/null; then
    echo "cancelled"
    exit 1
fi

python3 - "$BROKER" "$READER" "$WINDOW_SECS" "$LOG" <<'PYEOF'
import socket, struct, sys, time

broker, reader, window, log = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]

def enc_rem(n):
    out = b""
    while True:
        b = n % 128; n //= 128
        if n: out += bytes([b | 128])
        else: out += bytes([b]); break
    return out

def mstr(s):
    b = s.encode(); return struct.pack(">H", len(b)) + b

try:
    s = socket.create_connection((broker, 1883), timeout=10)
except OSError as e:
    print(f"broker unreachable: {e}"); sys.exit(2)

vh = mstr("MQTT") + bytes([4, 0x02]) + struct.pack(">H", 60)
p = vh + mstr("f3-drill-monitor")
s.sendall(b"\x10" + enc_rem(len(p)) + p)
body = b""
while len(body) < 4:
    body += s.recv(4 - len(body))
if body[-1] != 0:
    print(f"broker refused connection (rc={body[-1]})"); sys.exit(2)

sub = struct.pack(">H", 1)
for t in (f"access/{reader}/presence", f"access/{reader}/auth", f"access/{reader}/cmd"):
    sub += mstr(t) + bytes([0])
s.sendall(b"\x82" + enc_rem(len(sub)) + sub)

logf = open(log, "w")
def note(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    logf.write(line + "\n"); logf.flush()

note(f"monitoring {reader} on {broker} for {window}s (log: {log})")
seen = {"presence": False, "auth": False, "grant": False}
deadline = time.time() + window
s.settimeout(1.0)
buf = b""
last_ping = time.time()

while time.time() < deadline and not seen["grant"]:
    # MQTT keepalive: broker drops us after ~90 s without PINGREQ
    if time.time() - last_ping > 30:
        s.sendall(b"\xc0\x00")
        last_ping = time.time()
    try:
        d = s.recv(4096)
        if not d:
            note("broker closed connection"); break
        buf += d
    except socket.timeout:
        continue

    # extract complete PUBLISH packets from the stream
    while buf:
        if buf[0] >> 4 != 3:
            buf = buf[1:]          # skip control bytes (SUBACK/PINGRESP/...)
            continue
        j, mult, rl = 1, 1, 0
        complete = True
        while True:
            if j >= len(buf):
                complete = False; break
            b = buf[j]; rl += (b & 127) * mult; mult *= 128; j += 1
            if not (b & 128): break
        if not complete or j + rl > len(buf):
            break                  # incomplete packet — wait for more bytes
        tlen = struct.unpack(">H", buf[j:j+2])[0]
        topic = buf[j+2:j+2+tlen].decode(errors="replace")
        payload = buf[j+2+tlen:j+rl].decode(errors="replace")
        note(f"{topic} -> {payload[:160]}")
        if topic.endswith("/presence"):
            if "offline" in payload:
                note("door presence: offline (retained last-will — node not connected)")
            else:
                seen["presence"] = True
                note(">>> door node ONLINE")
        if topic.endswith("/auth"):
            seen["auth"] = True
            note(">>> tap detected: tag SUN read OK, tuple published")
        if topic.endswith("/cmd"):
            if '"grant":true' in payload.replace(" ", ""):
                seen["grant"] = True
                note(">>> GRANT received — relay should have pulsed (F3 PASS)")
            else:
                note(">>> decision received (no grant yet — first tap may deny once; keep holding)")
        buf = buf[j + rl:]

if seen["grant"]:
    sys.exit(0)
missing = [k for k in ("presence", "auth", "grant") if not seen[k]]
note(f"window elapsed; not seen: {', '.join(missing)}")
sys.exit(1)
PYEOF
RC=$?

if [ "$RC" = 0 ]; then
    zenity --info --title="KeyGate F3 drill" --text="GRANT received.

Did the relay physically click?
If yes: F3 bench drill PASS.

Log: ${LOG}" 2>/dev/null
    echo "F3 DRILL: GRANT"
elif [ "$RC" = 2 ]; then
    zenity --info --title="KeyGate F3 drill" --text="Could not connect to broker ${BROKER}.

Log: ${LOG}" 2>/dev/null
    echo "F3 DRILL: broker unreachable"
else
    zenity --info --title="KeyGate F3 drill" --text="No grant within ${WINDOW_SECS}s. Diagnostics:

- no presence  : door offline (power / WiFi)
- no auth      : tag not read — SUN/NDEF not provisioned correctly
- cmd deny bad_cmac      : SUN mirror layout mismatch (verifier cmac input — see docs/PN532-SPI-NOTES.md)
- cmd deny counter_replay (once) : normal on first tap, keep holding

Log: ${LOG}" 2>/dev/null
    echo "F3 DRILL: no grant"
fi
exit $RC
