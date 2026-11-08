# Port description

Detailed handshake protocol and timing for `aes_gcm_aead`.

## Reset

`rst_ni` is **synchronous active-low**. Hold it low for at least 4
clock cycles before the first command. After de-assertion, the core is
in `T_IDLE` with `init_ready_o = 1`.

```
clk_i      __|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_
rst_ni     ‾‾‾‾‾‾‾|_______________________|‾‾‾‾‾‾‾‾‾‾‾‾‾‾
init_ready_o      X X X X X X X X X X X X X 1 1 1 1 1 1
```

## Session start

A new AEAD session is initiated by pulsing `init_i` for one cycle
together with the key, nonce, and mode. The core internally:

1. Encrypts `0^128` with the AES key to derive the GHASH subkey `H`
   (~12 cycles).
2. Encrypts `J0 = nonce || 0x00000001` with the AES key to derive the
   tag-mask block `E0` (~12 cycles).
3. Begins accepting AAD or data.

```
clk_i               |‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_
init_ready_o        ‾‾‾|___________________________________
init_i              ___|‾‾|_____________________________________
key_i / nonce_i     ___|valid|___________________________________
mode_i              ___|valid|___________________________________
                    (H + E0 derive ~24 cycles)
aad_ready_o         _________________________|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
```

`init_ready_o` is high when the core can accept a new `init_i`, which
includes both `T_IDLE` (post-reset / post-clean) and `T_DONE` (after a
prior session has finalised). Driving `init_i` while `init_ready_o = 0`
is ignored.

## AAD streaming

Each AAD chunk is 1..16 bytes. The caller sends 16-byte chunks until
the last one, which can be partial. Per NIST SP 800-38D §7.1, partial
chunks are zero-padded internally to 16 bytes before being absorbed
into GHASH — the caller does NOT need to zero-pad explicitly (the byte
count signal is enough).

```
clk_i               |‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_
aad_ready_o         ‾‾‾‾‾‾|________________|‾‾‾‾‾‾|________|‾‾
aad_valid_i         ___|‾‾|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|‾‾|‾‾‾‾‾‾‾‾‾‾‾|___
aad_chunk_i         ___|c0 |‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|c1 |‾‾‾‾‾‾‾‾‾‾‾|___
aad_byte_count_i    ___|16 |                  |12 |              ___
aad_last_i          ___|0  |                  |1  |              ___
```

`aad_byte_count_i = 16` for full chunks; `1..15` for the last partial.
After accepting an AAD chunk, the core takes ~128 cycles to absorb it
through GHASH (one GF(2^128) multiply); during that window
`aad_ready_o` is low.

If the message has no AAD, simply skip the AAD phase: send
`data_valid_i` directly, and the FSM transitions automatically.

## Plaintext / ciphertext streaming

Each data block is 1..16 bytes. The result block (encrypted ciphertext
or decrypted plaintext) is emitted in lock-step with the input.

```
clk_i               |‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_
data_ready_o        ‾‾|_______________________|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
data_valid_i        |‾‾|_____________________________________
data_i              |b0 |_____________________________________
data_byte_count_i   |16 |_____________________________________
                    (AES_CTR ~12 cycles)
result_valid_o      _________________________|‾‾|________
result_o            _________________________|r0 |________
result_ready_i      _____________________________|‾‾|____
                    (GHASH absorb ~128 cycles)
```

`data_byte_count_i = 16` for full blocks; `1..15` for the last partial.
`data_last_i = 1` together with `data_valid_i = 1` triggers automatic
finalisation: the core absorbs the trailing length block into GHASH,
XORs the GHASH state with E0, and arrives at `T_DONE` without an
explicit `finalize_i` pulse.

`result_byte_count_o` mirrors the input byte count; the upper unused
bytes of `result_o` for a partial last block are zeroed by the core.

## Finalisation

There are two ways to finalise:

1. **Implicit (recommended)**: pulse `data_last_i = 1` with the final
   `data_valid_i` beat. The core handles everything else.
2. **Explicit**: after all `data_valid_i` beats have been consumed,
   pulse `finalize_i = 1` for one cycle. Useful in streaming flows
   where the caller does not know in advance which beat is last, or
   for AAD-only sessions (no plaintext).

Either way, the core then:
1. Feeds the (`len64(aad_bits)` || `len64(ct_bits)`) 16-byte length
   block to GHASH.
2. Computes `tag = ghash_state XOR E0`.
3. Asserts `tag_valid_o = 1` with `tag_o` stable.

```
clk_i               |‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|
data_last_i         |‾‾|_____________________________________
                    (LEN block GHASH absorb + final XOR ~130 cycles)
tag_valid_o         _____________________________|‾‾‾‾‾‾‾‾‾‾‾‾‾‾
tag_o               _____________________________|tag |‾‾‾‾‾‾‾‾‾‾‾‾
```

`tag_valid_o` stays high until the next `init_i`. `tag_o` is stable
across this entire window.

## Constant-time tag compare

For the decrypt path, the caller drives `expected_tag_i` with the tag
received over the wire. The core combinationally computes
`tag_match_o = tag_valid_o && (tag_o ^ expected_tag_i == 0)`. It is
designed with no early-exit, so that the full 128-bit XOR-OR-zero is
always evaluated and `tag_match_o` does not leak partial-match
information. This is intended to be constant-time; not evaluated.

For the encrypt path, leave `expected_tag_i = 0` (or any value); the
caller will use `tag_o` directly.

## Mode select (`mode_i`)

`mode_i` is a status bit recorded for the integrator's benefit. The
hardware operations are identical for all three modes (AES-CTR XOR,
GHASH absorb), but the value is observed by the coverage collector. In **DECRYPT** mode the GHASH input is the
ciphertext (i.e., `data_i` itself, NOT the XOR result) per NIST
SP 800-38D §7.2; this is handled internally.

| Encoding | Mode      | Use                                    |
|----------|-----------|----------------------------------------|
| `2'b00`  | ENCRYPT   | Caller feeds plaintext, gets ciphertext + tag |
| `2'b01`  | DECRYPT   | Caller feeds ciphertext, gets plaintext + tag, then verifies via `expected_tag_i` |
| `2'b10`  | AAD_ONLY  | Caller feeds AAD only, no ct/pt; tag authenticates AAD alone |
| `2'b11`  | reserved  | Reserved for future modes (e.g., AES-256-GCM, not implemented). Treated as ENCRYPT for now. |

## Endianness

All wide buses use **big-endian** byte ordering, matching NIST SP 800-38D
on-the-wire convention:
- `key_i[127:120]` is byte 0 of the AES key.
- `nonce_i[95:88]` is byte 0 of the IV.
- `aad_chunk_i[127:120]` is byte 0 of the chunk.
- `data_i[127:120]` is byte 0 of the block.
- `result_o[127:120]` is byte 0 of the result block.
- `tag_o[127:120]` is byte 0 of the tag.

This matches the convention used by Python's `cryptography` library and
by reference implementations in OpenSSL / mbedTLS / WolfSSL when
serialising AES-GCM output.

## Latency summary

For a message with `A` bytes of AAD and `P` bytes of plaintext:

| Phase                          | Cycles                              |
|--------------------------------|-------------------------------------|
| Init capture                   | 1                                   |
| H derive (AES on 0^128)        | ~12                                 |
| E0 derive (AES on J0)          | ~12                                 |
| AAD absorb                     | `ceil(A / 16) * 128`                |
| Per-data-block (AES_CTR + GHASH)| `12 + 128 = 140`                   |
| Number of data blocks          | `ceil(P / 16)`                      |
| LEN block absorb               | 128                                 |
| Final XOR (tag)                | 1                                   |
| Total (rough)                  | `~26 + ceil(A/16)*128 + ceil(P/16)*140 + 128` |

For a typical TLS 1.3 record with ~16 bytes AAD and ~16 KB plaintext,
this is about 144 000 cycles, i.e. ~1.44 ms at 100 MHz (unverified
estimate). The throughput is dominated by GHASH; a Karatsuba GF(2^128)
multiplier (not included in this repository) could bring each absorb
down to ~5 cycles (unverified estimate).
