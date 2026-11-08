-- SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Commercial
--
-- VHDL-2008 wrapper for the SystemVerilog aes_gcm_aead module.
--
-- This entity exposes the AEAD core's port list in VHDL syntax. The
-- architecture instantiates the SystemVerilog module by component name;
-- mixed-language elaboration is supported natively by Vivado, Quartus,
-- ModelSim/Questa, and Aldec, and via the GHDL VHPI bridge for open
-- simulation.
--
-- Status: WRAPPER ONLY. The AEAD datapath itself remains in SystemVerilog
-- (rtl/*.sv). A native VHDL port of the datapath is listed as future work.
--
-- I/O contract: identical to aes_gcm_aead.sv (see PORT_DESCRIPTION.md).
--   * Single clock, active-low synchronous reset.
--   * Streaming AAD interface (16-byte chunks).
--   * Streaming data interface (16-byte blocks).
--   * 128-bit tag, optional constant-time match against expected_tag.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

entity aes_gcm_aead_vhdl is
  port (
    clk_i               : in  std_logic;
    rst_ni              : in  std_logic;

    init_i              : in  std_logic;
    key_i               : in  std_logic_vector(127 downto 0);
    nonce_i             : in  std_logic_vector( 95 downto 0);
    mode_i              : in  std_logic_vector(  1 downto 0);
    init_ready_o        : out std_logic;

    aad_valid_i         : in  std_logic;
    aad_chunk_i         : in  std_logic_vector(127 downto 0);
    aad_byte_count_i    : in  std_logic_vector(  4 downto 0);
    aad_last_i          : in  std_logic;
    aad_ready_o         : out std_logic;

    data_valid_i        : in  std_logic;
    data_i              : in  std_logic_vector(127 downto 0);
    data_byte_count_i   : in  std_logic_vector(  4 downto 0);
    data_last_i         : in  std_logic;
    data_ready_o        : out std_logic;

    result_valid_o      : out std_logic;
    result_o            : out std_logic_vector(127 downto 0);
    result_byte_count_o : out std_logic_vector(  4 downto 0);
    result_last_o       : out std_logic;
    result_ready_i      : in  std_logic;

    finalize_i          : in  std_logic;
    tag_o               : out std_logic_vector(127 downto 0);
    tag_valid_o         : out std_logic;

    expected_tag_i      : in  std_logic_vector(127 downto 0);
    tag_match_o         : out std_logic
  );
end entity aes_gcm_aead_vhdl;

architecture rtl of aes_gcm_aead_vhdl is

  component aes_gcm_aead
    port (
      clk_i               : in  std_logic;
      rst_ni              : in  std_logic;
      init_i              : in  std_logic;
      key_i               : in  std_logic_vector(127 downto 0);
      nonce_i             : in  std_logic_vector( 95 downto 0);
      mode_i              : in  std_logic_vector(  1 downto 0);
      init_ready_o        : out std_logic;
      aad_valid_i         : in  std_logic;
      aad_chunk_i         : in  std_logic_vector(127 downto 0);
      aad_byte_count_i    : in  std_logic_vector(  4 downto 0);
      aad_last_i          : in  std_logic;
      aad_ready_o         : out std_logic;
      data_valid_i        : in  std_logic;
      data_i              : in  std_logic_vector(127 downto 0);
      data_byte_count_i   : in  std_logic_vector(  4 downto 0);
      data_last_i         : in  std_logic;
      data_ready_o        : out std_logic;
      result_valid_o      : out std_logic;
      result_o            : out std_logic_vector(127 downto 0);
      result_byte_count_o : out std_logic_vector(  4 downto 0);
      result_last_o       : out std_logic;
      result_ready_i      : in  std_logic;
      finalize_i          : in  std_logic;
      tag_o               : out std_logic_vector(127 downto 0);
      tag_valid_o         : out std_logic;
      expected_tag_i      : in  std_logic_vector(127 downto 0);
      tag_match_o         : out std_logic
    );
  end component;

begin

  u_aead : aes_gcm_aead
    port map (
      clk_i               => clk_i,
      rst_ni              => rst_ni,
      init_i              => init_i,
      key_i               => key_i,
      nonce_i             => nonce_i,
      mode_i              => mode_i,
      init_ready_o        => init_ready_o,
      aad_valid_i         => aad_valid_i,
      aad_chunk_i         => aad_chunk_i,
      aad_byte_count_i    => aad_byte_count_i,
      aad_last_i          => aad_last_i,
      aad_ready_o         => aad_ready_o,
      data_valid_i        => data_valid_i,
      data_i              => data_i,
      data_byte_count_i   => data_byte_count_i,
      data_last_i         => data_last_i,
      data_ready_o        => data_ready_o,
      result_valid_o      => result_valid_o,
      result_o            => result_o,
      result_byte_count_o => result_byte_count_o,
      result_last_o       => result_last_o,
      result_ready_i      => result_ready_i,
      finalize_i          => finalize_i,
      tag_o               => tag_o,
      tag_valid_o         => tag_valid_o,
      expected_tag_i      => expected_tag_i,
      tag_match_o         => tag_match_o
    );

end architecture rtl;
