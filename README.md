# aes-gcm-fpga-core

[![License: GPL-3.0-or-later or commercial](https://img.shields.io/badge/license-GPL--3.0%20%7C%20commercial-blue.svg)](LICENSE.md)

> **Status: experimental and unverified.** This core was written with AI assistance and has not been independently verified in simulation regressions, formal proofs or hardware. Claims in this repository about standards compliance, test results, timing and resource use are unverified. It has not been validated under NIST CAVP/CMVP and has not been evaluated for side-channel or fault-injection resistance. Do not use it in production or security-sensitive designs without your own verification. No support or maintenance is provided.

A small, synthesisable AES-128-GCM AEAD IP core in SystemVerilog.
Implements the NIST SP 800-38D algorithm (not validated) for the 96-bit
IV path: AES-128 in CTR mode for confidentiality, GHASH over GF(2^128)
for authentication, AEAD construction with AAD support, and a tag
compare intended to be constant-time (not evaluated). Targets
iCE40, ECP5, Xilinx 7-series, Cyclone V, and Tang Nano 9K.

NIST SP 800-38D Appendix B vectors and 100 random vectors generated with
Python's `cryptography.hazmat.primitives.ciphers.aead.AESGCM` are included
in the testbench; results not independently confirmed. No FPGA hardware is required to run
the test suite.

## NONCE-REUSE WARNING

AES-GCM is **catastrophically broken** by repeated `(key, IV)` pairs.
Encrypting two messages under the same key with the same IV leaks:

1. The XOR of the two plaintexts (CTR keystream reuse).
2. The hash subkey `H = AES_K(0^128)` — recoverable from the two
   tag-and-ciphertext pairs. With `H` in hand an attacker can forge
   tags arbitrarily for any future message under that key.

This core does **not** detect or prevent IV reuse. The integrator MUST
guarantee uniqueness of every `(key, IV)` pair. If you cannot prove
uniqueness, use a nonce-misuse-resistant AEAD (AES-GCM-SIV, RFC 8452
— not implemented here) or ChaCha20-Poly1305 with an extended nonce
(see the sibling [chacha20poly1305-fpga-core](https://github.com/ayoub-ac/chacha20poly1305-fpga-core)
project). Read [`SECURITY.md`](SECURITY.md) before deploying.

## Why this exists

AES-GCM is the most-deployed AEAD in production. TLS 1.2 / TLS 1.3,
IPsec ESP, MACsec / IEEE 802.1AE, SSH, and disk encryption all use it.
Free FPGA cores for AES-GCM are rare, almost always shipped without
NIST vectors / SVA / a real testbench, and almost never document their
nonce-reuse threat model honestly. This core is small, dual-licensed
cleanly (GPL for OSS, commercial for closed-source), shipped with a
real handshake protocol, NIST SP 800-38D vectors in the testbench,
SystemVerilog assertions, functional coverage, and a synthesis-comparison
report across multiple toolchains.

## Quickstart

```bash
git clone https://github.com/ayoub-ac/aes-gcm-fpga-core.git
cd aes-gcm-fpga-core
make lint test            # Verilator lint + run NIST + random vectors
make synth_report         # SYNTH_REPORT.md across iCE40/ECP5/Xilinx/Vivado/Quartus
```

Requires Verilator 5.0+ for simulation. Yosys 0.30+ for the open synth
flow. Python 3 with `cryptography` for `make regen_vectors`.

## Architecture

```
                  +-------------------------+
       key_i ---->|                         |
     nonce_i ---->|     aes_gcm_aead        |---> result_o (ct/pt)
       aad_i ---->|     (top-level FSM)     |---> result_byte_count_o
      data_i ---->|                         |---> tag_o (128-bit)
       init_i---->|                         |---> tag_match_o (CT compare)
   finalize_i---->|  ready_o / valid_o      |
                  +------------+------------+
                               |
              +----------------+-----------------+
              |                                  |
          aes_core                          ghash_core
       (FIPS-197 AES-128,              (NIST SP 800-38D §6.4
        iterative, 12 cycles            GF(2^128) shift-and-add,
        per block, shared encrypt/      128 cycles per multiply)
        decrypt datapath)
              |
              +-> aes_round (combinational SubBytes / ShiftRows /
              |              MixColumns / AddRoundKey)
              +-> aes_key_expand (FIPS-197 §5.2 key schedule)
              +-> aes_sbox / aes_inv_sbox (FIPS-197 Figure 7 / 14)
```

Top-level FSM phases: `IDLE -> DERIVE_H -> DERIVE_E0 -> AAD_RX ->
AAD_GH -> DATA_KS -> DATA_XOR -> DATA_GH -> LEN_GH -> TAG -> DONE`.
The FSM is designed to handle zero-padding of partial AAD / ciphertext
chunks per SP 800-38D §7.1 and to emit the final
`(len64(aad_bits) || len64(ct_bits))` block to GHASH automatically. Cycle
counts in the diagram are design intent and unverified.

## Port table

| Signal              | Dir | Width | Description                                                                                  | Spec ref |
|---------------------|-----|-------|----------------------------------------------------------------------------------------------|----------|
| `clk_i`             | in  | 1     | System clock, all flops sample on rising edge.                                                | -        |
| `rst_ni`            | in  | 1     | Synchronous active-low reset; hold low ≥4 cycles before first command.                        | -        |
| `init_i`            | in  | 1     | Pulse for one cycle to start a new session with `key_i / nonce_i / mode_i`.                   | -        |
| `key_i`             | in  | 128   | AES-128 key, byte 0 in `key_i[127:120]`.                                                      | FIPS-197 §5 |
| `nonce_i`           | in  | 96    | 96-bit IV, byte 0 in `nonce_i[95:88]`.                                                        | SP 800-38D §7.1 |
| `mode_i`            | in  | 2     | 00=encrypt, 01=decrypt, 10=AAD-only.                                                          | -        |
| `init_ready_o`      | out | 1     | High when the core can accept a new `init_i`.                                                 | -        |
| `aad_valid_i`       | in  | 1     | Asserted with `aad_chunk_i / aad_byte_count_i / aad_last_i` to feed AAD.                      | §7.1     |
| `aad_chunk_i`       | in  | 128   | 16-byte AAD chunk; bytes beyond `aad_byte_count_i` are masked internally.                     | §7.1     |
| `aad_byte_count_i`  | in  | 5     | Valid bytes in `aad_chunk_i` (1..16). 16 means a full chunk.                                  | -        |
| `aad_last_i`        | in  | 1     | Marks the final AAD chunk.                                                                    | -        |
| `aad_ready_o`       | out | 1     | Core ready to accept an AAD beat (handshake: `aad_valid_i && aad_ready_o`).                   | -        |
| `data_valid_i`      | in  | 1     | Asserted with `data_i / data_byte_count_i / data_last_i` to feed plaintext / ciphertext.      | §7.1     |
| `data_i`            | in  | 128   | 16-byte data block; bytes beyond `data_byte_count_i` are don't-care.                          | §7.1     |
| `data_byte_count_i` | in  | 5     | Valid bytes in `data_i` (1..16). 16 means a full block.                                       | -        |
| `data_last_i`       | in  | 1     | Marks the final data block. Triggers automatic finalisation.                                  | -        |
| `data_ready_o`      | out | 1     | Core ready to accept a data beat.                                                             | -        |
| `result_valid_o`    | out | 1     | Result block valid; consumer must assert `result_ready_i` to consume.                         | -        |
| `result_o`          | out | 128   | Output ciphertext (encrypt) or plaintext (decrypt) block.                                     | -        |
| `result_byte_count_o`| out | 5    | Valid bytes in `result_o`.                                                                    | -        |
| `result_last_o`     | out | 1     | High on the final result block.                                                               | -        |
| `result_ready_i`    | in  | 1     | Master asserts to consume `result_o`.                                                         | -        |
| `finalize_i`        | in  | 1     | Pulse to finalise (alternative to `data_last_i` for streaming flows).                         | -        |
| `tag_o`             | out | 128   | 128-bit GCM tag, byte 0 in `tag_o[127:120]`.                                                  | §7.1     |
| `tag_valid_o`       | out | 1     | Tag is valid and stable.                                                                      | -        |
| `expected_tag_i`    | in  | 128   | Caller-provided expected tag for the tag compare.                                             | -        |
| `tag_match_o`       | out | 1     | `(tag_o == expected_tag_i) && tag_valid_o`; intended to be constant-time, not evaluated.      | -        |

## Headline numbers

Unverified estimates (Yosys 0.x, AEAD top with all sub-modules); they
have not been independently reproduced:

| Target           | LUT       | FF    | BRAM | Latency (1 KB msg)    | Notes                  |
|------------------|-----------|-------|------|-----------------------|------------------------|
| iCE40 UP5K       | see `SYNTH_REPORT.md` | ~3000 | 0    | ~9000 cycles          | LUT4 generic, no DSP   |
| ECP5 LFE5UM-25   | see `SYNTH_REPORT.md` | ~3000 | 0    | ~9000 cycles          | abc9, no DSP inference |
| Xilinx Artix-7   | see `SYNTH_REPORT.md` | ~3000 | 0    | ~9000 cycles          | Yosys generic mapping  |

The 16x AES S-box LUT network and the 128-cycle GHASH multiplier
dominate area cost. Vendor flows (Vivado / Diamond / Quartus) are
expected to fold the S-boxes into block RAM and reduce the gate count
(unverified); `synth_xilinx`
shown here uses the open generic mapping. See
[`RESOURCE_ESTIMATES.md`](RESOURCE_ESTIMATES.md) for the full breakdown
and reduction options.

## Build & test

You need [Verilator](https://verilator.org/) 5.0 or newer.

```bash
make lint            # static check the RTL (sbox + key_expand + round +
                     # core + ghash + aead)
make test            # build and run AEAD test suite (NIST + 100 random)
make test-ghash      # GHASH multiplier unit tests (50 random pairs)
make test-all        # both suites
```

The harness is written to end a passing run with `+PASS all tests passed` and
exit 0. No passing run has been independently confirmed.

## Verification

Three techniques are wired into the testbench. Test vectors are included;
results not independently confirmed.

### Directed tests (6 named cases + 4 supporting tests)

| # | Test                                       | Coverage                                             |
|---|--------------------------------------------|------------------------------------------------------|
| 1 | NIST SP 800-38D Appendix B TC1             | Empty K, P, A — tag-only                             |
| 2 | NIST SP 800-38D Appendix B TC2             | K=0, P=0^128 (one zero block), A=empty               |
| 3 | NIST SP 800-38D Appendix B TC3             | 64-byte P, real K/IV, no AAD                         |
| 4 | NIST SP 800-38D Appendix B TC4             | 60-byte P (3 full + partial), 20-byte AAD            |
| 5 | Directed (cryptography ref, vec[0])        | Expected values from the `AESGCM` library            |
| 6 | Directed (cryptography ref, vec[1])        | Expected values from the `AESGCM` library            |
| 7 | Tampered expected_tag rejected             | `tag_match_o` compare                                |
| 8 | 100 random vectors                         | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` |
| 9 | Mode coverage (encrypt / decrypt / AAD-only)| All `mode_i` encodings                              |
| 10 | Empty plaintext, empty AAD                | Boundary case                                        |

NIST SP 800-38D Appendix B Test Cases 5 and 6 use 8-byte and 60-byte
IVs respectively, which require a separate GHASH-based J0 derivation
step. The shipped core supports the 96-bit-IV path only — the only one
used by TLS 1.2/1.3, IPsec ESP, SSH, and MACsec. Variable-length IV is
not implemented.

Plus a dedicated GHASH unit suite:
* `make test-ghash`: 50 random GF(2^128) multiplies compared against a
  software GHASH reference implementing NIST SP 800-38D Algorithm 1;
  results not independently confirmed.

### SystemVerilog assertions

`tb/aes_gcm_assertions.sv` is intended to check protocol invariants on
every cycle of every test:

- `data_ready_o` only rises after `init_i` has been seen.
- `result_o` is stable while back-pressured (`result_valid_o && !result_ready_i`).
- `tag_o` is stable while `tag_valid_o`.
- `tag_valid_o` only rises after an effective finalisation
  (`finalize_i` pulse OR a `data_last_i` beat).
- Tag latency bound after finalisation (`< LAT_MAX = 4096` cycles).

The assertions are intended to compile with both Verilator 5.x (`--assert`)
and Vivado xsim (not independently confirmed). They are stripped on synthesis flows via `` `ifndef SYNTHESIS ``.

### Functional coverage

`tb/aes_gcm_cov.sv` collects 11 bins. The simulator prints a coverage
summary at end-of-test in this format (illustrative output; results not independently confirmed):

```
---- Functional coverage ----
  [HIT ] mode_encrypt / mode_decrypt / mode_aad_only
  [HIT ] aad_seen / data_short / data_long
  [HIT ] partial_last / full_last
  [HIT ] finalize_seen / tag_emitted
  [HIT ] tag_mismatch
Coverage: 11/11 bins (100.0%)
```

The harness is intended to fail a run that drops below 100%.

### Synthesis comparison report

`make synth_report` runs every available toolchain on the same RTL and
emits [`SYNTH_REPORT.md`](SYNTH_REPORT.md) with a side-by-side LUT/FF/BRAM
table. Yosys (`synth_ice40` / `synth_ecp5` / `synth_xilinx`) is mandatory;
Vivado and Quartus are detected automatically and skipped with a notice
when not on `$PATH`.

## Variants

| Variant                             | Use case                                                                       |
|-------------------------------------|--------------------------------------------------------------------------------|
| `rtl/aes_gcm_aead.sv`               | Default AEAD top: encrypt / decrypt / AAD-only, 96-bit IV, single clock domain |
| `rtl/aes_core.sv`                   | AES-128 core only (no GCM)                                                     |
| `rtl/ghash_core.sv`                 | GHASH GF(2^128) multiplier only                                                |
| `vhdl_wrapper/aes_gcm_aead_vhdl.vhd`| VHDL-2008 entity wrapping the SV core for VHDL-only designs                    |

Roadmap (not implemented):
* AES-256-GCM (256-bit key variant — most defence / FIPS-favoured deployments).
* Variable-length IV path (NIST SP 800-38D §7.1, IV != 96 bits).
* Karatsuba GF(2^128) multiplier (5-cycle absorb instead of 128-cycle).
* Pipelined AES (1 keystream block per cycle).
* Side-channel hardening (masked AES + masked GHASH).
* AES-GCM-SIV (RFC 8452, nonce-misuse-resistant).

## License

Dual-licensed:

- **GPL-3.0-or-later** for open-source projects. If your product links
  this RTL or its compiled bitstream, your project must also be
  GPL-3.0+.
- **Commercial license** for closed-source products. Commercial licenses are available on request: open a GitHub issue titled 'Commercial license request'. Do not post confidential details in the issue. Any commercial license is provided as is, without warranty, support or maintenance. This core is unverified (see README).
  See [`LICENSE.md`](LICENSE.md) for the license text.

If unsure which applies, read `LICENSE.md` or open an issue.

## Repository layout

```
rtl/                       RTL sources
  aes_sbox.sv                forward S-box (FIPS-197 Fig. 7)
  aes_inv_sbox.sv            inverse S-box (FIPS-197 Fig. 14)
  aes_key_expand.sv          AES-128 key schedule (§5.2)
  aes_round.sv               combinational round (encrypt + decrypt)
  aes_core.sv                iterative AES-128 cipher engine
  ghash_core.sv              GHASH GF(2^128) multiplier
  aes_gcm_aead.sv            AEAD top-level
tb/                        testbench
  sim_main.cpp               C++ harness, NIST vectors, 10 test groups
  sim_main_ghash.cpp         GHASH unit harness
  aes_gcm_tb.sv              DUT wrapper + assertion + coverage bind
  ghash_tb.sv                GHASH unit DUT wrapper
  aes_gcm_assertions.sv      SVA properties
  aes_gcm_cov.sv             functional coverage collector
  nist_sp800_38d_vectors.sv  NIST vectors (for non-Verilator simulators)
  random_vectors.h           generated reference vectors
  gen_random_vectors.py      regenerator (uses `cryptography` lib)
vhdl_wrapper/              VHDL-2008 wrapper for mixed-language designs
scripts/                   helper scripts (synth_report.sh, vhdl_cosim.sh,
                           ghash_ref.py)
Makefile                   build/lint/sim/synth/synth_report/vhdl-test
```

## Contributing

Bug reports and patches welcome. Process:

1. File an issue first for non-trivial changes.
2. Fork, branch, and run `make lint test-all` locally.
3. Open a pull request with a description of what changed and why.
4. There is no CI; include the output of your local `make lint test-all`
   run in the pull request.

## Citation

```bibtex
@misc{aes-gcm-fpga-core,
  title  = {{aes-gcm-fpga-core}: a small dual-licensed AES-128-GCM AEAD IP core in SystemVerilog},
  author = {Achour, Ayoub},
  year   = {2026},
  howpublished = {\url{https://github.com/ayoub-ac/aes-gcm-fpga-core}}
}
```

## References

- NIST FIPS-197, *Advanced Encryption Standard (AES)*, November 2001.
- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation:
  Galois/Counter Mode (GCM) and GMAC*, November 2007.
- D. McGrew and J. Viega, *The Galois/Counter Mode of Operation (GCM)*,
  May 2005.
- IETF RFC 5288, *AES Galois Counter Mode (GCM) Cipher Suites for TLS*,
  August 2008.
- IETF RFC 8452, *AES-GCM-SIV: Nonce Misuse-Resistant
  Authenticated Encryption*, April 2019.

## Author

Ayoub Achour - [github.com/ayoub-ac](https://github.com/ayoub-ac)
