"""Frames the tests feed the pipeline, secured the way Thread secures them.

A frame counts as a sighting of its sender only when its MIC says the
sender holds the network key and used that extended address as its
nonce, and its frame counter is above the last accepted (pipeline
_verify). So a test frame that is meant to be heard from a device
carries a real MIC under the key the test's decryptor holds, and a
counter that climbs per source. Nothing else about the frame matters
to the pipeline, which reads the parsed Frame fields: the psdu is for
the decryptor alone.
"""

import struct

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from threadwatch.crypto import derive_keys

KEY = bytes(16)           # what stub_decryptor() holds
PAN = 0x4e21
_counters: dict = {}


def next_counter(src: str) -> int:
    """The next MAC frame counter for a source: climbs per process, so a
    device heard in one test is never "replaying" in the next."""
    _counters[src] = _counters.get(src, 0) + 1
    return _counters[src]


def secured_psdu(src_ext: str, counter: int, *, ftype: int = 1, seq: int = 0, pan: int = PAN,
                 dst: str = "0000", payload: bytes = b"\x7f\x33\xf0\x11\x22", key: bytes = KEY,
                 sequence: int = 0) -> bytes:
    """An 802.15.4 frame from an extended source, secured as Thread does
    (ENC-MIC-32, key index mode) under a key sequence, without FCS as the
    sniffer delivers it. ftype 3 is a data request: the command id is
    authenticated, not encrypted, and the payload is empty."""
    dst = dst or "ffff"
    fcf = ftype | 0x0008 | 0x0040 | ((2 if len(dst) == 4 else 3) << 10) | (1 << 12) | (3 << 14)
    header = struct.pack("<HBH", fcf, seq & 0xFF, pan) + bytes.fromhex(dst)[::-1] + bytes.fromhex(src_ext)[::-1]
    aux = bytes([0x0D]) + struct.pack("<L", counter) + bytes([(sequence & 0x7f) + 1])
    open_part = header + aux + (b"\x04" if ftype == 3 else b"")
    body = b"" if ftype == 3 else payload
    _mle, mac_key = derive_keys(key, sequence)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", counter) + bytes([5])
    return open_part + AESCCM(mac_key, tag_length=4).encrypt(nonce, body, open_part)


def psdu_for(src: str, *, counter=None, **kw) -> bytes:
    """secured_psdu for an extended source with the next counter; b"" for
    a short source, whose identity the pipeline resolves by other means."""
    if not src or len(src) != 16:
        return b""
    return secured_psdu(src, next_counter(src) if counter is None else counter, **kw)
