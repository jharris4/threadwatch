"""parse_mle: the MLE decryption path and its failure arms.

crypto.py reached 94.6% as a by-product of test_identity's short-address
matrices, with the uncovered remainder being exactly the failure paths,
and nobody owning them. The one that matters most is the retry across key
generations at a rotation: it is a `continue`, not a raise, so if it broke
MLE would stop decrypting mid-rotation, mle_rejoin_attempt and partition
reporting would go quiet, and nothing would say so.
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from threadwatch.crypto import Decryptor, derive_keys

KEY = bytes(range(16))
SED = "029a47566a00b543"
SRC_IP = bytes.fromhex("fe80000000000000") + bytes.fromhex("009a47566a00b543")
DST_IP = bytes.fromhex("ff020000000000000000000000000001")


def mle_mode1(src_ext: str, sequence: int, counter: int, body: bytes,
              src_ip: bytes = SRC_IP, dst_ip: bytes = DST_IP) -> bytes:
    """A secured MLE message with key id mode 1: the key identifier is the
    one-byte index, so the receiver has to search the generations that map
    to it rather than being told the sequence (mode 2, test_identity)."""
    aux = bytes([5 | (1 << 3)]) + struct.pack("<L", counter) + bytes([(sequence & 0x7f) + 1])
    mle_key, _mac = derive_keys(KEY, sequence)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", counter) + bytes([5])
    return bytes([0]) + aux + AESCCM(mle_key, tag_length=4).encrypt(nonce, body, src_ip + dst_ip + aux)


def advertisement(partition: int = 0x0a0b0c0d, leader_router: int = 60, rloc16: int = 0xc800) -> bytes:
    """An MLE Advertisement carrying Source Address and Leader Data TLVs."""
    source_addr = bytes([0, 2]) + struct.pack(">H", rloc16)
    leader_data = bytes([11, 8]) + struct.pack(">L", partition) + bytes([0, 0, 0, leader_router])
    return bytes([4]) + source_addr + leader_data


class ParseMleTest(unittest.TestCase):
    def _parse(self, d, payload):
        return d.parse_mle(payload, SED, SRC_IP, DST_IP)

    def test_a_secured_advertisement_decrypts_and_its_tlvs_are_read(self):
        d = Decryptor(network_key=KEY)
        info = self._parse(d, mle_mode1(SED, 1000, 7, advertisement()))
        self.assertIsNotNone(info)
        self.assertEqual((info.command, info.command_name, info.secured), (4, "Advertisement", True))
        self.assertEqual((info.partition_id, info.leader_router_id, info.source_addr16, info.counter),
                         (0x0a0b0c0d, 60, 0xc800, 7))
        self.assertEqual(d.stats["mle_decrypted"], 1)
        self.assertEqual(d.stats["mle_failed"], 0)
        # The sender told us which short address it holds, which unlocks
        # MAC decryption of its short-source data frames.
        self.assertEqual(d.short_to_ext["c800"], SED)
        self.assertEqual(d.key_sequence, 1000)

    def test_a_straggler_on_the_previous_key_decrypts_on_the_second_try(self):
        # A key index maps to a generation every 128 sequences, so at a
        # rotation the nearest candidate is the wrong one and the loop has
        # to carry on past its InvalidTag. This is the retry the whole
        # rotation depends on.
        d = Decryptor(network_key=KEY)
        d.note_key_sequence(1000)
        candidates = [seq for seq, _mle, _mac in d._keys_for_index((1000 & 0x7f) + 1)]
        self.assertEqual(candidates[:2], [1000, 872])          # the current key first, then a rotation back
        info = self._parse(d, mle_mode1(SED, 872, 3, advertisement()))
        self.assertIsNotNone(info)
        self.assertEqual(info.command_name, "Advertisement")
        self.assertEqual(d.stats["mle_failed"], 0)
        self.assertEqual(d.key_sequence, 1000)                 # a straggler does not pull the search back
        # ...and the generation ahead, the one a rotation moves to, reads too.
        self.assertIsNotNone(self._parse(d, mle_mode1(SED, 1128, 4, advertisement())))
        self.assertEqual(d.key_sequence, 1128)                 # this one does move it up

    def test_a_message_no_generation_decrypts_is_counted_and_returns_none(self):
        d = Decryptor(network_key=KEY)
        d.note_key_sequence(1000)
        self.assertIsNone(self._parse(d, mle_mode1(SED, 100_000, 1, advertisement())))
        self.assertEqual(d.stats["mle_failed"], 1)
        self.assertEqual(d.stats["mle_decrypted"], 0)
        # A wrong network key is the same answer, counted the same way.
        other = Decryptor(network_key=bytes(16))
        self.assertIsNone(other.parse_mle(mle_mode1(SED, 1000, 1, advertisement()), SED, SRC_IP, DST_IP))
        self.assertEqual(other.stats["mle_failed"], 1)

    def test_what_says_nothing_about_the_credentials_is_not_a_failure(self):
        d = Decryptor(network_key=KEY)
        full = mle_mode1(SED, 1000, 1, advertisement())
        for what, payload in (
            ("empty", b""),
            ("unknown security suite", bytes([7]) + full[1:]),
            # Mode 0 carries no key identifier: nothing to search under.
            ("key id mode 0", bytes([0, 5]) + full[2:]),
            ("shorter than its own security header", full[:8]),
            ("no source address to build the nonce from", None),
        ):
            with self.subTest(what):
                if payload is None:
                    self.assertIsNone(d.parse_mle(full, None, SRC_IP, DST_IP))
                else:
                    self.assertIsNone(self._parse(d, payload))
        # Missing IPv6 addresses: the auth data cannot be rebuilt.
        self.assertIsNone(d.parse_mle(full, SED, None, DST_IP))
        self.assertIsNone(d.parse_mle(full, SED, SRC_IP, None))
        self.assertEqual(d.stats["mle_failed"], 0)
        self.assertEqual(d.stats["mle_decrypted"], 0)

    def test_an_unsecured_message_is_reported_by_command_and_counted_apart(self):
        # Security suite 255 (Discovery Request/Response) carries no MIC, so
        # anything on the channel can send one: the command, and nothing else.
        d = Decryptor(network_key=KEY)
        info = self._parse(d, bytes([255, 16]) + b"whatever TLVs")
        self.assertEqual((info.command, info.command_name, info.secured), (16, "Discovery Request", False))
        self.assertIsNone(info.partition_id)
        self.assertIsNone(info.source_addr16)
        self.assertEqual(d.stats["mle_unsecured"], 1)
        self.assertIsNone(self._parse(d, bytes([255])))        # the command byte is not there
        self.assertEqual(d.stats["mle_unsecured"], 1)

    def test_a_command_with_no_name_is_reported_by_number(self):
        d = Decryptor(network_key=KEY)
        info = self._parse(d, mle_mode1(SED, 1000, 1, bytes([99])))
        self.assertEqual((info.command, info.command_name), (99, "cmd99"))

    def test_a_tlv_run_that_does_not_add_up_stops_rather_than_raising(self):
        d = Decryptor(network_key=KEY)
        # A Leader Data TLV claiming eight bytes with four present, and a
        # length of 255, which the parser treats as the end of the run.
        for body in (bytes([4]) + bytes([11, 8]) + b"\x00\x01\x02\x03",
                     bytes([4]) + bytes([0, 255]) + b"\x00\x02\xc8\x00"):
            info = self._parse(d, mle_mode1(SED, 1000, 1, body))
            self.assertEqual(info.command_name, "Advertisement")
            self.assertIsNone(info.partition_id)
            self.assertIsNone(info.source_addr16)

    def test_a_key_index_outside_the_protocol_has_no_candidates(self):
        d = Decryptor(network_key=KEY)
        for bad in (0, 129, 255):
            self.assertEqual(d._keys_for_index(bad), [], bad)
        self.assertEqual(len(d._keys_for_index(1)), d.INITIAL_GENERATIONS)


if __name__ == "__main__":
    unittest.main()
