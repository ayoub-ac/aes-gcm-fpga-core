# SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
"""Reference GHASH and AES-GCM test for cross-validation.

Used to verify the directional convention of `ghash_core.sv` matches
NIST SP 800-38D / Python `cryptography` AESGCM output before wiring
the hardware testbench. Not part of the build flow; lives in scripts/
for ad-hoc debugging.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def gf128_mul(x: int, y: int) -> int:
    """Multiply two 128-bit GF(2^128) elements in NIST GCM convention.

    Inputs/outputs are 128-bit ints where:
      bit 127 is byte 0 bit 7 (the leftmost bit of the leftmost byte),
      bit 120 is byte 0 bit 0,
      bit 119 is byte 1 bit 7, ...
      bit 0   is byte 15 bit 0 (the rightmost bit of the rightmost byte).

    In NIST polynomial mapping bit 127 = x^0, bit 0 = x^127. The shift in
    the algorithm therefore moves coefficients toward higher x-power by
    going from bit 127 -> bit 0 (i.e. a shift-right in the integer).
    """
    R = 0xE1 << 120
    z = 0
    v = y
    for i in range(128):
        # NIST bit 0 of x is the leftmost bit, which is bit 127 of the int.
        bit = (x >> (127 - i)) & 1
        if bit:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z & ((1 << 128) - 1)


def block_to_int(b: bytes) -> int:
    """16-byte block -> 128-bit integer in the convention above."""
    if len(b) != 16:
        raise ValueError("block must be 16 bytes")
    return int.from_bytes(b, "big")


def int_to_block(n: int) -> bytes:
    return (n & ((1 << 128) - 1)).to_bytes(16, "big")


def ghash(h: bytes, data: bytes) -> bytes:
    """Pure-Python GHASH used as oracle."""
    if len(data) % 16 != 0:
        raise ValueError("ghash data must be multiple of 16 bytes (caller pads)")
    H = block_to_int(h)
    Y = 0
    for off in range(0, len(data), 16):
        X = block_to_int(data[off : off + 16])
        Y = gf128_mul(Y ^ X, H)
    return int_to_block(Y)


def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """Use the cryptography library's primitive AES via Cipher (ECB)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def aes_gcm_encrypt(key: bytes, iv: bytes, aad: bytes, pt: bytes):
    """Hand-rolled AES-128-GCM as a self-test of the GHASH convention."""
    if len(iv) != 12:
        raise ValueError("only 12-byte IV supported by this reference")
    H = aes_ecb_encrypt(key, b"\x00" * 16)
    J0 = iv + b"\x00\x00\x00\x01"

    def inc32(blk: bytes) -> bytes:
        ctr = int.from_bytes(blk[12:], "big")
        ctr = (ctr + 1) & 0xFFFFFFFF
        return blk[:12] + ctr.to_bytes(4, "big")

    # CTR encrypt
    ct = bytearray()
    ctr = inc32(J0)
    for off in range(0, len(pt), 16):
        ks = aes_ecb_encrypt(key, ctr)
        block = pt[off : off + 16]
        ct.extend(bytes(a ^ b for a, b in zip(block, ks)))
        ctr = inc32(ctr)

    # Build GHASH input: aad || pad16(aad) || ct || pad16(ct) || len64(aad bits) || len64(ct bits)
    def pad16(b):
        if len(b) % 16 == 0:
            return b
        return b + b"\x00" * (16 - len(b) % 16)

    blob = pad16(aad) + pad16(bytes(ct)) + (len(aad) * 8).to_bytes(8, "big") + (
        len(ct) * 8
    ).to_bytes(8, "big")
    S = ghash(H, blob)

    # tag = AES_K(J0) XOR S
    j0_enc = aes_ecb_encrypt(key, J0)
    tag = bytes(a ^ b for a, b in zip(j0_enc, S))
    return bytes(ct), tag


def selftest() -> None:
    """Cross-check our hand-rolled AES-GCM against `cryptography` library."""
    import os, random

    random.seed(0xA1B2C3D4)
    for n in range(20):
        key = os.urandom(16)
        iv = os.urandom(12)
        aad_len = random.randint(0, 32)
        pt_len = random.randint(0, 80)
        aad = os.urandom(aad_len)
        pt = os.urandom(pt_len)

        ct1, tag1 = aes_gcm_encrypt(key, iv, aad, pt)
        ref = AESGCM(key).encrypt(iv, pt, aad if aad_len else None)
        ct2, tag2 = ref[:-16], ref[-16:]
        assert ct1 == ct2, (ct1.hex(), ct2.hex())
        assert tag1 == tag2, (tag1.hex(), tag2.hex())
    print("ghash_ref selftest: 20/20 PASS")


if __name__ == "__main__":
    selftest()
