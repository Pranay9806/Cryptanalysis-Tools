"""
Tool 08: MD4 / Merkle-Damgård Length Extension Cryptanalysis Engine
Course Outcome: CO3 (MD4 Attack)
Author: Pranay Shaunjay P.V (Roll No: 24pc20)
"""

import struct
from typing import Dict, Tuple

class MD4LengthExtensionTool:
    """
    Demonstrates the Length Extension Attack on Merkle-Damgård construction hash functions (like MD4 and MD5).
    When an unkeyed hash is used as a naive MAC:
        MAC = MD4(secret || message)
    an attacker knowing only len(secret), message, and MAC can append arbitrary data:
        MAC' = MD4(secret || message || original_padding || extension)
    without ever knowing the secret!
    """

    @staticmethod
    def md4_padding(msg_len_bytes: int) -> bytes:
        """Constructs MD4 standard Merkle-Damgard padding (1 bit followed by zeros and 64-bit length)."""
        bit_len = msg_len_bytes * 8
        pad = b'\x80'
        mod = (msg_len_bytes + 1) % 64
        if mod <= 56:
            pad += b'\x00' * (56 - mod)
        else:
            pad += b'\x00' * (64 + 56 - mod)
        pad += struct.pack('<Q', bit_len)
        return pad

    @staticmethod
    def _left_rotate(val: int, n: int) -> int:
        return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _f(x, y, z): return (x & y) | (~x & z)
    @staticmethod
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    @staticmethod
    def _h(x, y, z): return x ^ y ^ z

    @classmethod
    def md4_compress_block(cls, state: Tuple[int, int, int, int], block: bytes) -> Tuple[int, int, int, int]:
        """Runs MD4 compression on a single 64-byte block using given initial internal state."""
        a, b, c, d = state
        X = list(struct.unpack('<16I', block))

        # Round 1
        for i in range(16):
            s = [3, 7, 11, 19][i % 4]
            a = cls._left_rotate((a + cls._f(b, c, d) + X[i]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        # Round 2
        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i in range(16):
            s = [3, 5, 9, 13][i % 4]
            a = cls._left_rotate((a + cls._g(b, c, d) + X[order2[i]] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        # Round 3
        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            s = [3, 9, 11, 15][i % 4]
            a = cls._left_rotate((a + cls._h(b, c, d) + X[order3[i]] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        return ((state[0] + a) & 0xFFFFFFFF,
                (state[1] + b) & 0xFFFFFFFF,
                (state[2] + c) & 0xFFFFFFFF,
                (state[3] + d) & 0xFFFFFFFF)

    @classmethod
    def compute_md4(cls, data: bytes, init_state=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476), total_len_override=None) -> Tuple[str, Tuple[int, int, int, int]]:
        state = init_state
        length = total_len_override if total_len_override is not None else len(data)
        padded = data + cls.md4_padding(length)
        for i in range(0, len(padded), 64):
            state = cls.md4_compress_block(state, padded[i:i+64])
        digest = struct.pack('<4I', *state).hex()
        return digest, state

    def forge_extension(self, original_hash: str, secret_len: int, original_msg: bytes, extension: bytes) -> Dict:
        """
        Calculates forged hash without knowing the secret key.
        """
        # 1. Unpack original hash into internal MD4 state registers (A, B, C, D)
        state = struct.unpack('<4I', bytes.fromhex(original_hash))

        # 2. Reconstruct original padding that was hashed by the victim
        orig_pad = self.md4_padding(secret_len + len(original_msg))

        # 3. Virtual length of the extended message
        total_len = secret_len + len(original_msg) + len(orig_pad) + len(extension)

        # 4. Hash extension starting directly from internal state
        forged_digest, _ = self.compute_md4(extension, init_state=state, total_len_override=total_len)

        return {
            "status": "FORGERY_SUCCESSFUL",
            "original_hash": original_hash,
            "forged_hash": forged_digest,
            "extended_payload_hex": (original_msg + orig_pad + extension).hex(),
            "explanation": "State registers extracted from known hash; compression resumed without knowledge of secret."
        }

def run_tool():
    tool = MD4LengthExtensionTool()
    # Victim secret
    secret = b"MySuperSecretKey"
    original_msg = b"action=view_balance&user=alice"
    orig_hash, _ = tool.compute_md4(secret + original_msg)

    # Attacker performs extension
    extension = b"&action=transfer&amount=1000000&to=eve"
    attack_res = tool.forge_extension(orig_hash, secret_len=len(secret), original_msg=original_msg, extension=extension)

    # Verification: Does MD4(secret || original_msg || pad || extension) equal the forged hash?
    orig_pad = tool.md4_padding(len(secret) + len(original_msg))
    actual_extended_hash, _ = tool.compute_md4(secret + original_msg + orig_pad + extension)

    attack_res["verified"] = (attack_res["forged_hash"] == actual_extended_hash)
    return attack_res

if __name__ == "__main__":
    print(run_tool())
