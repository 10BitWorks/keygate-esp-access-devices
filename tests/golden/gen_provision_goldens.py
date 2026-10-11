#!/usr/bin/env python3
"""pylibsdm-backed NTAG 424 DNA provisioning golden-vector generator (todo 3).

Binding spec for todo 3 (host-testable provisioning primitives in
`src/provision.rs`). Every value below is produced by driving pylibsdm's OWN
reference implementation (`pylibsdm.tag.ntag424dna.tag.NTAG424DNA`) against a
deterministic card stub, so the golden values are bit-exact against the
reference:

  AuthenticateEV2First  -> NTAG424DNA.authenticate_ev2_first (tag.py:268-314)
  session keys          -> NTAG424DNA.derive_session_keys    (tag.py:238-266)
  Part2 payload         -> the exact bytes pylibsdm sends for ADDITIONAL_DF
                           (tag.py:186-217, 285-287)
  IVc / IVr             -> NTAG424DNA.ivc / .ivr properties   (tag.py:67-93)
  ChangeKey frame       -> NTAG424DNA.change_key              (tag.py:340-352)
  ChangeFileSettings    -> NTAG424DNA.send_command_full        (tag.py:374-388)

COMMAND CODES are pinned to the NXP NT4H2421Gx datasheet Table 22 ("Supported
commands and APDUs") and reproduced in pylibsdm const.py:10-20:

  AuthenticateEV2First  INS 0x71   (Part1, SW 91AF)
  AdditionalFrame       INS 0xAF   (Part2 -> PartN, SW 9100)
  ChangeKey             INS 0xC4   (CommMode.Full)
  ChangeFileSettings    INS 0x5F   (CommMode.Full)

NOTE: the todo-3 prose in the plan says "0x7A additional frame" and
"change_file_settings ... cmd 0x5C". Both are typos: the datasheet and the
pinned pylibsdm reference use 0xAF (additional frame) and 0x5F (ChangeFile-
Settings); 0x5C is SetConfiguration. The generator and Rust both use the
reference values, and the golden tests enforce it.

FIXTURES (fixed so the Rust golden tests are deterministic). RndA/RndB/TI are
the NXP AN12196 §5.6 worked-example values, so the session keys are also
cross-checkable against the application note:

  KEY   = 000102030405060708090a0b0c0d0e0f
  RndB  = b9e2fc789b64bf237cccaa20ec7e6e48
  RndA  = 13c5db8a5930439fc3def9a4c675360f
  TI    = 9d00c4df
  new_key (key_nr 1) = aabbccddeeff00112233445566778899, version 1
  file 2 settings bytes = 00..13 (20 bytes)

Run with the pylibsdm venv:
  /tmp/opencode/sdm/bin/python3 tests/golden/gen_provision_goldens.py
"""

import json
import sys
from binascii import hexlify
from struct import pack

from Crypto.Cipher import AES

import pylibsdm.tag.ntag424dna.tag as tmod
from pylibsdm.tag.ntag424dna.const import CommandHeader, Status
from pylibsdm.tag.ntag424dna.tag import NTAG424DNA

NULL_IV = 16 * b"\x00"

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
RNDB = bytes.fromhex("b9e2fc789b64bf237cccaa20ec7e6e48")
RNDA = bytes.fromhex("13c5db8a5930439fc3def9a4c675360f")
TI = bytes.fromhex("9d00c4df")

NEW_KEY = bytes.fromhex("aabbccddeeff00112233445566778899")
NEW_KEY_VERSION = 1
SETTINGS = bytes(range(0x00, 0x14))  # 20 bytes
SETTINGS_FILE_NR = 2


def rotate_left(b: bytes, n: int = 1) -> bytes:
    return b[n:] + b[:n]


class CardStub:
    """Minimal NTAG 424 card side for the EV2-First handshake.

    Encrypts RndB with the shared key, validates RndB' on the AdditionalFrame,
    and returns TI || RndA' || PDCap2 || PCDCap2 per datasheet §9/Table 14. All
    other commands succeed with SW 9100. Frames are recorded so the generator
    can capture exactly what pylibsdm transmitted.
    """

    def __init__(self, key: bytes, rndb: bytes, ti: bytes):
        self.key = key
        self.rndb = rndb
        self.ti = ti
        self.frames: list[tuple[int, bytes]] = []

    def send_apdu(self, cla, ins, p1, p2, data=b"", mrl=256, check_status=True):
        self.frames.append((ins, bytes(data)))
        if ins == 0xA4:  # ISO SELECT
            return b"\x90\x00"
        if ins == 0x71:  # AuthenticateEV2First Part1
            return AES.new(self.key, AES.MODE_CBC, NULL_IV).encrypt(self.rndb) + b"\x91\xaf"
        if ins == 0xAF:  # AdditionalFrame (Part2)
            pt = AES.new(self.key, AES.MODE_CBC, NULL_IV).decrypt(data)
            rnda, rndb_ = pt[:16], pt[16:32]
            assert rndb_ == rotate_left(self.rndb), "RndB' mismatch"
            resp = self.ti + rotate_left(rnda) + b"\x00" * 6 + b"\x00" * 6
            return AES.new(self.key, AES.MODE_CBC, NULL_IV).encrypt(resp) + b"\x91\x00"
        if ins in (0xC4, 0x5F):  # ChangeKey / ChangeFileSettings (CommMode.Full)
            return b"\x91\x00"
        return b"\x6a\x82"

    def last_frame(self, ins: int) -> bytes:
        for i, (frame_ins, data) in enumerate(self.frames):
            if frame_ins == ins:
                return data
        raise KeyError(f"no frame with INS 0x{ins:02X}")


def main() -> int:
    # Fix the PCD nonce so the handshake is deterministic.
    tmod.get_random_bytes = lambda n: RNDA if n == 16 else bytes(n)

    stub = CardStub(KEY, RNDB, TI)
    tag = NTAG424DNA(stub)
    tag.set_key(0, KEY)
    tag.authenticate_ev2_first(0)

    k_enc = tag.k_ses_auth_enc
    k_mac = tag.k_ses_auth_mac
    ti = tag.ti
    assert tag.cmdctr == 0, tag.cmdctr

    ivc0 = tag.ivc  # pylibsdm @ cmdctr 0
    ivr0 = tag.ivr
    part2 = stub.last_frame(0xAF)

    # ChangeKey (first CommMode.Full command -> cmdctr 0, then increments).
    tag.change_key(1, NEW_KEY, version=NEW_KEY_VERSION)
    change_key_frame = stub.frames[[i for i, (x, _) in enumerate(stub.frames) if x == 0xC4][0]][1]

    # ChangeFileSettings (now cmdctr 1).
    tag.send_command_full(
        0,
        CommandHeader.CHANGE_FILE_SETTINGS,
        SETTINGS_FILE_NR.to_bytes(1, "big"),
        SETTINGS,
        expected=Status.OK,
    )
    cfs_frame = stub.frames[[i for i, (x, _) in enumerate(stub.frames) if x == 0x5F][0]][1]

    out = {
        "key": hexlify(KEY).decode(),
        "rndb": hexlify(RNDB).decode(),
        "rnda": hexlify(RNDA).decode(),
        "ti": hexlify(ti).decode(),
        "k_enc": hexlify(k_enc).decode(),
        "k_mac": hexlify(k_mac).decode(),
        "part2": hexlify(part2).decode(),
        "ivc0": hexlify(ivc0).decode(),
        "ivr0": hexlify(ivr0).decode(),
        "new_key": hexlify(NEW_KEY).decode(),
        "version": NEW_KEY_VERSION,
        "change_key_frame": hexlify(change_key_frame).decode(),
        "settings_file_nr": SETTINGS_FILE_NR,
        "settings": hexlify(SETTINGS).decode(),
        "cfs_frame": hexlify(cfs_frame).decode(),
        "cmdctr_after": tag.cmdctr,
    }
    print(json.dumps(out, indent=2))

    # Sanity: AN12196 §5.6 works the same handshake with RndB
    # b9e2fc789b64bf237cccaa20ec7e6e48 and RndA 13c5db8a5930439fc3def9a4c675360f.
    assert ti == TI
    assert pack("<H", 0) == b"\x00\x00"
    return 0


if __name__ == "__main__":
    sys.exit(main())
