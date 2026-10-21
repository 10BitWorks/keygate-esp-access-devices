#!/usr/bin/env python3
"""OTA push: stream a firmware image to a keygate node over MQTT.

Usage: scripts/ota-push.py [image] [device] [broker] [--wait-secs N] [--expect-rollback --sha <hex>]

Positional arguments (backward-compatible):
  image        path to firmware .bin (default: /tmp/keygate-app.bin)
  device       device id prefix in access/<id>/... (default: keygate1)
  broker       MQTT broker hostname or IP (default: 10.7.1.106)

Options:
  --wait-secs N           budget in seconds for post-end boot banner wait (default: 90)
  --expect-rollback       wait for rollback banner differing from --sha instead of first banner
  --sha HEX               git sha of pushed image (required with --expect-rollback)

Protocol (matches src/ota.rs):
  access/<id>/ota/meta  {"size":N,"crc32":"XXXXXXXX"}   (CRC32 = zlib)
  access/<id>/ota/data  raw 512-byte chunks, in order, QoS 1
  access/<id>/ota/end   {}

The device verifies size+CRC, writes the otadata entry (seq+1, VALID),
reboots into the new slot, and re-publishes its boot banner (with the new
git sha) to access/<id>/log — this script prints those lines as proof.
"""
import argparse
import hashlib
import json
import re
import ssl
import sys
import time
import zlib

parser = argparse.ArgumentParser(
    description="OTA push: stream a firmware image to a keygate node over MQTT."
)
parser.add_argument(
    "image",
    nargs="?",
    default="/tmp/keygate-app.bin",
    help="path to firmware .bin (default: /tmp/keygate-app.bin)",
)
parser.add_argument(
    "device",
    nargs="?",
    default="keygate1",
    help="device id prefix in access/<id>/... (default: keygate1)",
)
parser.add_argument(
    "broker",
    nargs="?",
    default="10.7.1.106",
    help="MQTT broker hostname or IP (default: 10.7.1.106)",
)
parser.add_argument(
    "--wait-secs",
    type=int,
    default=90,
    help="budget in seconds for post-end boot banner wait (default: 90)",
)
parser.add_argument(
    "--expect-rollback",
    action="store_true",
    help="wait for rollback banner differing from --sha instead of first banner",
)
parser.add_argument(
    "--sha",
    type=str,
    default=None,
    help="git sha of pushed image (required with --expect-rollback)",
)

args = parser.parse_args()

if args.expect_rollback and not args.sha:
    parser.error("--expect-rollback requires --sha <hex>")

import paho.mqtt.client as mqtt

IMAGE = args.image
DEVICE = args.device
BROKER = args.broker
WAIT_SECS = args.wait_secs
EXPECT_ROLLBACK = args.expect_rollback
TARGET_SHA = args.sha.lower().strip() if args.sha else None

data = open(IMAGE, "rb").read()
while len(data) % 4:
    data += b"\xff"  # pad to word boundary
crc = zlib.crc32(data) & 0xFFFFFFFF
print(f"image: {len(data)} bytes, crc32 {crc:08x}")

meta_t = f"access/{DEVICE}/ota/meta"
data_t = f"access/{DEVICE}/ota/data"
end_t = f"access/{DEVICE}/ota/end"
log_t = f"access/{DEVICE}/log"
status_t = f"access/{DEVICE}/ota/status"

state = {"logs": [], "statuses": [], "connected": False, "subbed": False}

FW_GIT_RE = re.compile(r"fw git:([0-9a-fA-F]+)")


ROLLBACK_KEYWORDS = ("probation", "rollback", "ota:", "attempt")

def on_connect(c, userdata, flags, rc, props=None):
    state["connected"] = True
    c.subscribe([(log_t, 1), (status_t, 1)])


def on_subscribe(c, userdata, mid, reason_codes, props=None):
    state["subbed"] = True


def on_message(c, userdata, msg):
    line = msg.payload.decode("utf-8", "replace")
    if msg.topic == status_t:
        state["statuses"].append(line)
        print(f"[status] {line}")
        if EXPECT_ROLLBACK:
            lower_line = line.lower()
            if any(k in lower_line for k in ROLLBACK_KEYWORDS):
                print(f"[drill] {line}")
    else:
        state["logs"].append(line)
        print(f"[node] {line}")
        if EXPECT_ROLLBACK:
            lower_line = line.lower()
            if any(k in lower_line for k in ROLLBACK_KEYWORDS):
                print(f"[drill] {line}")


cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ota-push")
cli.on_connect = on_connect
cli.on_subscribe = on_subscribe
cli.on_message = on_message
cli.connect(BROKER, 1883, keepalive=30)
cli.loop_start()
for _ in range(50):
    if state["subbed"]:
        break
    time.sleep(0.1)
if not state["subbed"]:
    print("broker connect/subscribe failed")
    sys.exit(1)
time.sleep(1.0)

print(f"meta -> {meta_t}")
cli.publish(meta_t, json.dumps({"size": len(data), "crc32": f"{crc:08x}"}, separators=(',', ':')), qos=1).wait_for_publish()

print("waiting for device to finish batched erase (status: receiving)...")
t_wait = time.time()
last_heartbeat = t_wait
erased = False
while time.time() - t_wait < 120:
    for s in state["statuses"]:
        if "receiving" in s:
            erased = True
            break
        if "failed" in s or "aborted" in s:
            print(f"erase failed: {s}")
            sys.exit(3)
    if erased:
        break
    now = time.time()
    if now - last_heartbeat >= 5.0:
        elapsed = int(now - t_wait)
        print(f"waiting for erase... {elapsed}s elapsed")
        last_heartbeat = now
    time.sleep(0.2)

if not erased:
    print("timeout waiting for device erase completion — check node")
    sys.exit(3)

print("device ready — streaming data chunks...")
CHUNK = 512
t0 = time.time()
for off in range(0, len(data), CHUNK):
    # wire format: [u32 LE offset][bytes] — idempotent under QoS1 dupes
    pkt = off.to_bytes(4, "little") + data[off:off + CHUNK]
    cli.publish(data_t, pkt, qos=1).wait_for_publish()
    time.sleep(0.02)  # pace: the device erases/writes flash per chunk
    if (off // CHUNK) % 40 == 0:
        print(f"data: {off}/{len(data)} bytes")
print(f"data: done in {time.time() - t0:.1f}s")

print(f"end -> {end_t}")
cli.publish(end_t, "{}", qos=1).wait_for_publish()

print(f"waiting for reboot + boot banner (up to {WAIT_SECS}s)...")
deadline = time.time() + WAIT_SECS
sha_seen = False
confirmed_old_sha = None

# Track already inspected log index to avoid re-evaluating or missing lines
last_log_idx = 0

while time.time() < deadline:
    logs_len = len(state["logs"])
    while last_log_idx < logs_len:
        line = state["logs"][last_log_idx]
        last_log_idx += 1

        if EXPECT_ROLLBACK:
            if "fw git:" in line:
                m = FW_GIT_RE.search(line)
                observed_sha = m.group(1).lower() if m else ""
                # Rollback confirmed if observed sha differs from the pushed TARGET_SHA
                if (
                    TARGET_SHA
                    and observed_sha
                    and not (
                        observed_sha.startswith(TARGET_SHA)
                        or TARGET_SHA.startswith(observed_sha)
                    )
                ):
                    confirmed_old_sha = observed_sha
                    sha_seen = True
                    break
                else:
                    print(f"BOOT BANNER (pushed/provisional build): {line}")
        else:
            if "fw git:" in line:
                print(f"BOOT BANNER: {line}")
                sha_seen = True
                break

    if sha_seen:
        break
    time.sleep(1)

cli.loop_stop()

if EXPECT_ROLLBACK:
    if sha_seen and confirmed_old_sha:
        print(f"ROLLBACK CONFIRMED (sha {confirmed_old_sha})")
        sys.exit(0)
    else:
        print("Rollback drill failed — expected rollback banner not observed within timeout.")
        sys.exit(2)
else:
    print("OTA push complete." if sha_seen else "push sent — banner not observed (check the node).")
    sys.exit(0 if sha_seen else 2)
