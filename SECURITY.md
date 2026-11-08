# Security model

This document describes what `aes_gcm_aead` (and the underlying
`aes_core` and `ghash_core`) is designed to defend against, what it is
NOT designed to defend against, and how to evaluate the claims.

If you need a side-channel-resistant AEAD core for a real product, read
this whole document and decide whether the threat model matches your
deployment. Don't trust marketing copy; trust the threat model and your
own evaluation.

## NONCE-REUSE WARNING — read this first

GCM is **catastrophically broken** by nonce reuse. Encrypting two
messages under the same (key, IV) pair leaks:

1. The XOR of the two plaintexts (CTR-mode keystream reuse).
2. The hash subkey `H = AES_K(0^128)` — recoverable from any two
   tag-and-ciphertext pairs that share the IV. With H in hand an
   attacker can forge tags arbitrarily for any future message under
   that key.

This module does **not** detect or prevent nonce reuse. The integrator
MUST guarantee uniqueness of every (key, IV) pair across the lifetime
of the key. For a 96-bit IV under a single key:

- A counter-IV strategy (start at 0, increment per record) gives 2^96
  records before exhaustion — effectively unbounded.
- A random-IV strategy reaches the birthday bound at ~2^48 records.
  Past that point the probability of a collision becomes meaningful;
  TLS 1.3 mandates rekeying well before this.

If your system cannot provably maintain uniqueness, do NOT use AES-GCM.
Consider AES-GCM-SIV (RFC 8452, nonce-misuse-resistant) or
ChaCha20-Poly1305 with an XChaCha20 wrapper. AES-GCM-SIV is not
implemented in this core.

## What is intended to be protected (not evaluated)

### 1. Constant-time execution

The design is intended to be constant-time; not evaluated.

AES (FIPS-197) and GCM (NIST SP 800-38D) are designed to be implementable
without data-dependent branches. The cycle count of every FSM in this
core is intended to depend only on the (aad_len, pt_len) tuple and not
on the message bytes, the key, or the IV.

Per-block cycle counts (design intent, unverified):
* `aes_core`: 12 cycles per 128-bit block (1 setup + 10 round-key
  expansions + 10 round cycles + 1 done), regardless of key/data.
* `ghash_core`: 128 cycles per GF(2^128) multiply, regardless of
  operands.
* `aes_gcm_aead` top-level: deterministic per (aad_len, pt_len) tuple.

**What this is intended to protect (not evaluated)**: timing attacks
that observe completion latency to infer key or message bits. No path
through the design is intended to take a different number of cycles
depending on data values.

### 2. Constant-time tag compare

The `tag_match_o` output is computed combinationally as
`(tag_o ^ expected_tag_i) == 0`. It is designed with no early-exit, so
that the full 128-bit XOR-OR-zero is always evaluated. A naive
byte-by-byte memcmp performed in software risks leaking how many leading
bytes match; this hardware compare is intended not to, but it has not
been evaluated.

### 3. Bounded round and step counters

The internal AES round counter (0..10) and the GHASH bit counter (0..127)
are checked by SVA assertions intended to fail the test run if a
counter ever runs past its expected range (results not independently confirmed).

### 4. Strong AEAD properties from NIST SP 800-38D

The SP 800-38D construction provides the following properties, assuming a
correct implementation (this one is unverified):
* **Confidentiality**: AES-CTR is a strong stream cipher when used with
  a unique (key, IV) pair. See the nonce-reuse warning at the top of
  this document.
* **Integrity / authenticity**: GHASH binds the AAD, the ciphertext,
  and their lengths into a 128-bit tag through GF(2^128) multiplication
  by the secret subkey H. Modifying any byte of AAD, ciphertext, or the
  (aad_len, ct_len) tuple invalidates the tag.

## What is NOT covered (be honest)

This list is deliberately exhaustive so users can evaluate fit:

- **Differential power analysis (DPA)** on the AES round update or the
  GHASH accumulator: the working state and the GHASH multiplier inputs
  are unmasked. A power attacker measuring leakage at the FF-update
  boundary can mount standard CPA / DPA against intermediate values,
  including against the recoverable hash subkey H (see notes in the
  literature on "GCM DPA" — recovering H breaks integrity for the
  current key). Mitigation requires masked AES (e.g., threshold
  implementation, RAMBAM, domain-oriented masking) and a masked GHASH
  multiplier — neither is implemented.
- **Electromagnetic (EM) analysis** and **template attacks**: not
  specifically countered. There is no power balancing, no differential
  routing, no constant-Hamming-weight encoding.
- **Fault injection** on the round counter, AES state, the GHASH
  accumulator, or the message-feed FSM: a flipped bit can corrupt the
  output. No duplicated-counter / parity-protected register variant is
  implemented (the aes128-fpga-core sibling includes a variant intended
  to be hardened; not evaluated).
- **Cache / micro-architectural side channels**: not applicable (this
  is RTL, not software). However, if you place this core into a system
  with a shared bus or shared memory, those channels can leak.
- **Nonce-reuse misuse**: this core does NOT detect or prevent nonce
  reuse. See the warning at the top of this document. For a
  nonce-misuse-resistant AEAD use AES-GCM-SIV (RFC 8452); not
  implemented in this core.
- **Variable-length IV path (SP 800-38D §7.1, IV != 96 bits)**: this
  core supports the 96-bit IV path only — the only one used by TLS
  1.2/1.3, IPsec ESP, SSH, and MACsec. Variable-length IV requires a
  separate GHASH-based J0 derivation step and is not implemented.
- **Invasive attacks** (decap, microprobing) are entirely out of scope.

If your deployment threat model includes any of the above and the rest
of your system relies on AEAD integrity, this core is not enough on its
own.

## Compliance claims

- **NIST SP 800-38D conformance**: not validated. The RTL implements the
  SP 800-38D algorithm (not validated) for the 96-bit IV path: AES-128
  (FIPS-197), GHASH (SP 800-38D §6.4), and the AES-GCM AEAD
  construction (§7.1). Test vectors are included in the testbench;
  results not independently confirmed:
  * Appendix B Test Cases 1, 2, 3, 4 (the 96-bit-IV cases).
  * 100 random (key, IV, AAD, plaintext) tuples with expected values
    from `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
  * Appendix B Test Cases 5 and 6 (8-byte and 60-byte IVs) are NOT
    covered — that path is not implemented.
- **NIST CAVP test certificate**: NOT obtained. CAVP validation
  requires a NIST-accredited testing lab. The published Appendix B
  vectors and the Python `cryptography` reference are included for
  informal testing; results not independently confirmed.
- **FIPS-140-3 certification**: NOT claimed. AES-128-GCM is on the
  FIPS 140-3 approved-algorithm list; achieving an actual FIPS-140-3
  certificate requires a full module evaluation including
  side-channel and tamper response — not part of this product.
- **Common Criteria**: not evaluated.
- **TLS 1.2 / 1.3 / IPsec ESP / MACsec / SSH suitability**: this core
  implements the cryptographic primitive used by all of the above, but
  the protocol-level framing, IV construction, key schedule, rekeying,
  and replay protection are out of scope and must be implemented by the
  integrator.

## Test methodology used to validate the security claims

The Verilator testbenches contain the checks below. The checks are
included; results not independently confirmed.

1. **Functional correctness on NIST published vectors**: `make test`.
   The testbench includes Appendix B Test Cases 1, 2, 3, and 4 from
   SP 800-38D verbatim.
2. **Comparison against Python `cryptography`**: the testbench
   includes 100 randomly-generated (key, IV, AAD, plaintext) tuples,
   each encrypted by the Python reference and replayed through the
   DUT; the ciphertext + tag must match exactly. Lengths cover edge
   cases (0..7 bytes, 8..15 bytes, 16..23 bytes, and random up to 256).
3. **SVA-checked protocol invariants on every cycle**: see
   `tb/aes_gcm_assertions.sv`. Properties include:
   - `data_ready_o` only rises after `init_i` has been seen.
   - `result_o` is stable while `result_valid_o`.
   - `tag_o` is stable while `tag_valid_o`.
   - `tag_valid_o` only rises after an effective finalization.
   - Tag latency bound after finalization.
4. **Functional coverage**: 11 bins (encrypt / decrypt / aad-only modes,
   AAD seen, short / long data, partial / full last block, finalize
   and tag emission, plus an explicit tag-mismatch bin for the
   tampered-tag exercise). Coverage report printed at end of `make test`.

We do NOT run experimental DPA / CPA against a real bitstream. The
constant-time claim is **design intent**, derived from the structure of
the algorithm. An experimentally verified claim would require an FPGA,
an oscilloscope, and a trace-collection campaign measured in days or
weeks; none has been done.

## How to use the core safely

1. **Never reuse a (key, IV) pair.** This is the cardinal rule of
   AES-GCM. A 96-bit IV gives you 2^96 IVs per key — more than enough
   for a counter-IV strategy in any normal lifetime, but only if you
   actually maintain uniqueness.
2. Hold `rst_ni` low for at least 4 cycles after power-on and before
   the first command.
3. Wipe the message and key from memory after use; the wrapper does not
   do this automatically (the working-state registers retain post-op
   state until the next `init_i`).
4. For tag verification, use `tag_match_o` (intended to be constant-time;
   not evaluated) instead of
   reading `tag_o` and comparing in software.
5. The core is not a substitute for protocol-level measures like
   replay protection, rekeying, or padding-oracle hardening. Wrap it
   in a real protocol (TLS 1.3, IPsec ESP, MACsec, SSH).
6. If you cannot prove (key, IV) uniqueness in your system, switch to
   a nonce-misuse-resistant AEAD (AES-GCM-SIV, RFC 8452). AES-GCM-SIV
   is not implemented in this core.

## Reporting issues

Found a bug, a side channel we missed, or a discrepancy with NIST
SP 800-38D? Open a GitHub issue; do not post confidential details in it.
Coordinated disclosure welcome. We do not currently offer a bug bounty.
