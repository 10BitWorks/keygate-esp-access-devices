#!/usr/bin/env python3
"""OTA push: stream a firmware image to a keygate node over MQTT.

Usage: scripts/ota-push.py <image.bin> [device_id] [broker_host]

Protocol (matches src/ota.rs):
  access/<id>/ota/meta  {"size":N,"crc32":"XXXXXXXX"}   (CRC32 = zlib)
  access/<id>/ota/data  raw 512-byte chunks, in order, QoS 1
  access/<id>/ota/end   {}

The device verifies size+CRC, writes the otadata entry (seq+1, VALID),
reboots into the new slot, and re-publishes its boot banner (with the new
git sha) to access/<id>/log — this script prints those lines as proof.
"""
import hashlib
import json
import ssl
import sys
import time
import zlib

import paho.mqtt.client as mqtt

IMAGE = sys.argv[1] if len(sys.argv) > 1 else "/tmp/keygate-app.bin"
DEVICE = sys.argv[2] if len(sys.argv) > 2 else "keygate1"
BROKER = sys.argv[3] if len(sys.argv) > 3 else "10.7.1.106"

data = open(IMAGE, "rb").read()
while len(data) % 4:
    data += b"\xff"  # pad to word boundary
crc = zlib.crc32(data) & 0xFFFFFFFF
print(f"image: {len(data)} bytes, crc32 {crc:08x}")

meta_t = f"access/{DEVICE}/ota/meta"
data_t = f"access/{DEVICE}/ota/data"
end_t = f"access/{DEVICE}/ota/end"
log_t = f"access/{DEVICE}/log"

state = {"logs": [], "connected": False}


def on_connect(c, userdata, flags, rc, props=None):
    state["connected"] = True
    c.subscribe(log_t)


def on_message(c, userdata, msg):
    line = msg.payload.decode("utf-8", "replace")
    state["logs"].append(line)
    print(f"[node] {line}")


cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ota-push")
cli.on_connect = on_connect
cli.on_message = on_message
cli.connect(BROKER, 1883, keepalive=30)
cli.loop_start()
for _ in range(50):
    if state["connected"]:
        break
    time.sleep(0.1)
if not state["connected"]:
    print("broker connect failed")
    sys.exit(1)
time.sleep(0.5)

print(f"meta -> {meta_t}")
cli.publish(meta_t, json.dumps({"size": len(data), "crc32": f"{crc:08x}"}), qos=1).wait_for_publish()

CHUNK = 512
t0 = time.time()
for off in range(0, len(data), CHUNK):
    cli.publish(data_t, data[off:off + CHUNK], qos=1).wait_for_publish()
    if (off // CHUNK) % 40 == 0:
        print(f"data: {off}/{len(data)} bytes")
print(f"data: done in {time.time() - t0:.1f}s")

print(f"end -> {end_t}")
cli.publish(end_t, "{}", qos=1).wait_for_publish()

print("waiting for reboot + boot banner (up to 90s)...")
deadline = time.time() + 90
sha_seen = False
while time.time() < deadline:
    for line in state["logs"]:
        if "fw git:" in line:
            print(f"BOOT BANNER: {line}")
            sha_seen = True
            break
    if sha_seen:
        break
    time.sleep(1)

cli.loop_stop()
print("OTA push complete." if sha_seen else "push sent — banner not observed (check the node).")
sys.exit(0 if sha_seen else 2)
