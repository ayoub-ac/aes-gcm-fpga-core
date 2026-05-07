# VHDL wrapper

`aes_gcm_aead_vhdl.vhd` is a thin VHDL-2008 entity that re-exposes the
SystemVerilog `aes_gcm_aead` module under a VHDL-friendly interface. Use
it from a VHDL design that does not want to touch SystemVerilog directly.

## Status

**Wrapper only.** The AES-128 cipher, GHASH GF(2^128) multiplier, and AEAD
state machine all live in `rtl/*.sv` and are instantiated as a SystemVerilog
black-box. Mixed-language elaboration is supported by every commercial
simulator and synthesiser the core has been tested against.

A pure VHDL re-implementation of the datapath is on the roadmap (Premium
tier, scope: parity with `rtl/aes_gcm_aead.sv` including the same testbench
checks). Until then, treat this directory as a binding layer, not as a
second implementation.

## Usage

### Vivado / Quartus / Diamond

Add both the SystemVerilog files and `aes_gcm_aead_vhdl.vhd` to the same
project library (`work` is fine). The toolchain resolves the SV component
automatically:

```tcl
# Vivado
read_verilog -sv {rtl/aes_sbox.sv rtl/aes_inv_sbox.sv rtl/aes_key_expand.sv \
                   rtl/aes_round.sv rtl/aes_core.sv rtl/ghash_core.sv \
                   rtl/aes_gcm_aead.sv}
read_vhdl -vhdl2008 vhdl_wrapper/aes_gcm_aead_vhdl.vhd
```

### ModelSim / Questa / Aldec

```
vlog -sv rtl/aes_sbox.sv rtl/aes_inv_sbox.sv rtl/aes_key_expand.sv \
        rtl/aes_round.sv rtl/aes_core.sv rtl/ghash_core.sv rtl/aes_gcm_aead.sv
vcom -2008 vhdl_wrapper/aes_gcm_aead_vhdl.vhd
```

### GHDL + Verilator (open-source co-sim)

GHDL compiles the VHDL side, Verilator compiles the SV side, and the two
are linked through GHDL's VHPI bridge. The provided `make vhdl-test` target
wraps this; run it from the repository root:

```
make vhdl-test
```

The target is a no-op (with a notice) if `ghdl` is not on `$PATH`.

## Instantiation example

```vhdl
library ieee;
  use ieee.std_logic_1164.all;

entity my_design is end entity;
architecture rtl of my_design is
  signal clk, rstn                         : std_logic;
  signal init, init_ready                  : std_logic;
  signal key                               : std_logic_vector(127 downto 0);
  signal nonce                             : std_logic_vector( 95 downto 0);
  signal mode                              : std_logic_vector(  1 downto 0);
  signal aad_valid, aad_ready, aad_last    : std_logic;
  signal aad_chunk                         : std_logic_vector(127 downto 0);
  signal aad_bc                            : std_logic_vector(  4 downto 0);
  signal data_valid, data_ready, data_last : std_logic;
  signal data_in                           : std_logic_vector(127 downto 0);
  signal data_bc                           : std_logic_vector(  4 downto 0);
  signal result_valid, result_ready, result_last : std_logic;
  signal result_out                        : std_logic_vector(127 downto 0);
  signal result_bc                         : std_logic_vector(  4 downto 0);
  signal finalize, tag_valid, tag_match    : std_logic;
  signal tag, expected_tag                 : std_logic_vector(127 downto 0);
begin
  u_gcm : entity work.aes_gcm_aead_vhdl
    port map (
      clk_i               => clk,
      rst_ni              => rstn,
      init_i              => init,
      key_i               => key,
      nonce_i             => nonce,
      mode_i              => mode,
      init_ready_o        => init_ready,
      aad_valid_i         => aad_valid,
      aad_chunk_i         => aad_chunk,
      aad_byte_count_i    => aad_bc,
      aad_last_i          => aad_last,
      aad_ready_o         => aad_ready,
      data_valid_i        => data_valid,
      data_i              => data_in,
      data_byte_count_i   => data_bc,
      data_last_i         => data_last,
      data_ready_o        => data_ready,
      result_valid_o      => result_valid,
      result_o            => result_out,
      result_byte_count_o => result_bc,
      result_last_o       => result_last,
      result_ready_i      => result_ready,
      finalize_i          => finalize,
      tag_o               => tag,
      tag_valid_o         => tag_valid,
      expected_tag_i      => expected_tag,
      tag_match_o         => tag_match
    );
end architecture;
```

## What this wrapper does NOT change

* Latency, throughput, area: identical to `aes_gcm_aead.sv`. There is no
  additional pipeline stage. Per AEAD session: 12 cycles for H derivation,
  12 cycles for E0 derivation, 12 cycles per 16-byte CTR block, 128
  cycles per GHASH absorb, plus 1 cycle to register the tag.
* Endianness: byte 0 of the message is at bits `[127:120]` of every
  byte-stream port. That matches NIST SP 800-38D §5.2 byte conventions
  and the on-the-wire format produced by Python's `cryptography.hazmat
  .primitives.ciphers.aead.AESGCM`.
* Reset polarity: still active-low synchronous (`rst_ni`).
