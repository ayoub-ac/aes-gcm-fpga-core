# Resource estimates

Numbers below are from Yosys 0.x generic synthesis (`make synth_report`).
They are pre-place-and-route. See `SYNTH_REPORT.md` for the most recent
run; this document explains what dominates the area and how to shrink
it.

## Summary (post-Yosys, pre-PnR)

| Target                         | Comment |
|--------------------------------|---------|
| Lattice iCE40 UP5K             | LUT-heavy: the 16x AES S-box LUTs and the 128-cycle GHASH XOR tree both expand to LUT4 networks. Fits comfortably on the UP5K (5280 logic tiles). |
| Lattice ECP5 LFE5UM-25         | LUT4 dominates. ECP5 generic synthesis in Yosys 0.x does not auto-pack the AES round into `MULT18X18`; nextpnr-ecp5 packs tighter; vendor (Diamond) tighter still. |
| Xilinx Artix-7 XC7A35T         | Yosys-generic synthesis here counts LUT6 + CARRY4. Vivado synth_design will pack the AES S-box into BRAM18 if instructed and the LUT count drops sharply. |
| Cyclone V 5CSEMA5F31C6         | Quartus folds the AES S-box into M10K block RAMs; ALM count is much lower than the Yosys soft estimate. |
| Gowin GW1NR-9 (Tang Nano 9K)   | Not characterised here. Uses BRAM-backed S-box mapping; size comparable to ECP5 with vendor flow. |

For exact LUT/FF/BRAM numbers run `make synth_report` and read
`SYNTH_REPORT.md`. The synthesis-comparison report is regenerated on
every CI build.

## What dominates the area

- **AES S-box (16 instances per round)**: 16 lookup tables, each
  256-entry 8-bit. Yosys generic synthesis maps each S-box to a tree
  of LUT4/LUT6 cells (~80 LUT4 per S-box on iCE40; ~30 LUT6 on
  Artix-7). That's the single largest LUT contributor.
- **MixColumns + InvMixColumns combinational paths**: ~200 LUT4
  cells per AES round on iCE40.
- **GHASH multiplier**: a 128-cycle iterative shift-and-add. The
  combinational XOR tree per cycle is small (~256 LUT4 per cycle for
  the conditional-XOR step), but the design is iterative, so the
  hardware is one shift register + one XOR network — much smaller
  than a flat schoolbook multiplier.
- **AES key expansion**: 11 round keys x 128 bits = 1408 FFs of state
  for the round-key schedule. The combinational `aes_key_expand`
  module computes the next round key from the previous; we register
  all 11 round keys to allow either encrypt or decrypt to share the
  schedule.
- **Session / accumulator state**: 128b key + 96b nonce + 128b H +
  128b E0 + 128b GHASH acc + 32b CTR + 64+64b length counters + ~700b
  FSM / buffer registers ~ 1300 FFs.

## What you can do to shrink it

- **BRAM-mapped S-box**: replace the combinational `aes_sbox` with a
  256x8 ROM. Vivado / Quartus / Diamond do this automatically when the
  S-box is structured as a function of a single 8-bit input; the
  Yosys-generic flow does not. A `(* rom_style = "block" *)` attribute
  on the case statement reclaims roughly 40-50% of the LUT cost on
  Artix-7 and ECP5. Available in the Premium tier.
- **Karatsuba GHASH multiplier**: replace the 128-cycle iterative
  multiplier with a 5-cycle pipelined Karatsuba-3 design. Cuts GHASH
  latency by 25x at the cost of ~4-6k LUTs (combinational). Available
  in the Premium tier.
- **Single-S-box AES (8-bit datapath)**: serialise the 16 S-box
  invocations onto a single shared S-box, reducing AES area by ~10x at
  the cost of 16x latency per block. Reasonable for very small iCE40
  boards. Available in the Premium tier.
- **Decrypt-only / encrypt-only build**: drop `aes_inv_sbox` and the
  decrypt-side InvShiftRows / InvMixColumns network if the deployment
  only needs one direction. AEAD usage encrypts in both directions,
  but the *AES* engine inside our core only ever runs in encrypt
  direction (CTR mode is symmetric); a build flag to elide the inverse
  path saves ~30% of AES LUTs. Available in the Premium tier.

## What you can do to push throughput

- **Pipelined AES** (Premium): unroll the 10-round loop into a 10-stage
  pipeline. Steady-state throughput becomes 1 keystream block per cycle
  instead of every 12 cycles. Requires ~10x area for the AES engine.
- **Karatsuba GHASH** (Premium, see above): brings GHASH from 128
  cycles to 5 cycles per absorb. Combined with pipelined AES, this
  unlocks ~10 Gbps AES-GCM at 200 MHz on Artix-7.
- **Cache one keystream block ahead**: prefetch the next AES_CTR block
  while the current one is being XORed and consumed. Hides the
  12-cycle keystream generation latency behind the data flow on long
  messages.

## Frequency

- iCE40 UP5K, default toolchain (Yosys + nextpnr), no constraints:
  limited by the AES S-box LUT depth and the GHASH conditional-XOR
  combinational path (~30-40 MHz on generic synth).
- ECP5: ~80-100 MHz on generic synth.
- Artix-7 -1 speed grade: ~100 MHz typical with Yosys, easily 200+ MHz
  with Vivado + S-box BRAM mapping.
- Cyclone V: similar to Artix-7 with M10K-backed S-boxes.

The throughput is gated by both the cipher (1 keystream block per 12
cycles) and the MAC (1 chunk per 128 cycles). For a 1-KB message, the
AEAD finishes in roughly: 24 (init + H + E0) + 64 * 140 (AES + GHASH)
+ 128 (LEN absorb) ≈ 9100 cycles, i.e. ~9 cycles per byte. At 100 MHz
this gives about 90 Mbps; the pipelined Premium variant pushes this to
~10 Gbps on Artix-7 with DSP-mapped Karatsuba GHASH.

## Power

Ballpark: 20-40 mW dynamic on iCE40 UP5K at 30 MHz, depending on data
activity. The AES round update toggles ~1500 FFs every 12 cycles; the
GHASH state toggles every cycle during absorb. Static power is
dominated by the FPGA itself.

## How to reproduce

```bash
make synth_report
```

This runs Yosys with `synth_ice40`, `synth_ecp5` (with `-abc9`), and
`synth_xilinx`, then `stat`, and writes the result to
`SYNTH_REPORT.md`. Vendor flows (Vivado, Quartus) are detected
automatically when on PATH.

For end-to-end place-and-route numbers (post-PnR LUT counts and timing),
run the vendor flow:
- iCE40 / ECP5: `nextpnr-ice40` / `nextpnr-ecp5` with Yosys output.
- Xilinx: Vivado with a project pointing at the `rtl/` files.
- Lattice Diamond / Radiant: project with `rtl/` added.
- Quartus: project with `rtl/` added.
