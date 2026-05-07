// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// Top-level testbench wrapper for aes_gcm_aead.
// Stimulus from tb/sim_main.cpp.

module aes_gcm_tb (
  input  logic         clk_i,
  input  logic         rst_ni,

  input  logic         init_i,
  input  logic [127:0] key_i,
  input  logic [95:0]  nonce_i,
  input  logic [1:0]   mode_i,
  output logic         init_ready_o,

  input  logic         aad_valid_i,
  input  logic [127:0] aad_chunk_i,
  input  logic [4:0]   aad_byte_count_i,
  input  logic         aad_last_i,
  output logic         aad_ready_o,

  input  logic         data_valid_i,
  input  logic [127:0] data_i,
  input  logic [4:0]   data_byte_count_i,
  input  logic         data_last_i,
  output logic         data_ready_o,

  output logic         result_valid_o,
  output logic [127:0] result_o,
  output logic [4:0]   result_byte_count_o,
  output logic         result_last_o,
  input  logic         result_ready_i,

  input  logic         finalize_i,
  output logic [127:0] tag_o,
  output logic         tag_valid_o,

  input  logic [127:0] expected_tag_i,
  output logic         tag_match_o
);

  aes_gcm_aead u_dut (
    .clk_i              (clk_i),
    .rst_ni             (rst_ni),
    .init_i             (init_i),
    .key_i              (key_i),
    .nonce_i            (nonce_i),
    .mode_i             (mode_i),
    .init_ready_o       (init_ready_o),
    .aad_valid_i        (aad_valid_i),
    .aad_chunk_i        (aad_chunk_i),
    .aad_byte_count_i   (aad_byte_count_i),
    .aad_last_i         (aad_last_i),
    .aad_ready_o        (aad_ready_o),
    .data_valid_i       (data_valid_i),
    .data_i             (data_i),
    .data_byte_count_i  (data_byte_count_i),
    .data_last_i        (data_last_i),
    .data_ready_o       (data_ready_o),
    .result_valid_o     (result_valid_o),
    .result_o           (result_o),
    .result_byte_count_o(result_byte_count_o),
    .result_last_o      (result_last_o),
    .result_ready_i     (result_ready_i),
    .finalize_i         (finalize_i),
    .tag_o              (tag_o),
    .tag_valid_o        (tag_valid_o),
    .expected_tag_i     (expected_tag_i),
    .tag_match_o        (tag_match_o)
  );

  // ----------------------------------------------------------------
  // Bind the SVA + coverage modules.
  // ----------------------------------------------------------------
  aes_gcm_assertions u_assert (
    .clk_i          (clk_i),
    .rst_ni         (rst_ni),
    .init_i         (init_i),
    .data_valid_i   (data_valid_i),
    .data_ready_o   (data_ready_o),
    .data_last_i    (data_last_i),
    .result_valid_o (result_valid_o),
    .result_o       (result_o),
    .tag_valid_o    (tag_valid_o),
    .tag_o          (tag_o),
    .finalize_i     (finalize_i)
  );

  aes_gcm_cov u_cov (
    .clk_i             (clk_i),
    .rst_ni            (rst_ni),
    .init_i            (init_i),
    .mode_i            (mode_i),
    .aad_valid_i       (aad_valid_i),
    .aad_ready_o       (aad_ready_o),
    .data_valid_i      (data_valid_i),
    .data_ready_o      (data_ready_o),
    .data_last_i       (data_last_i),
    .data_byte_count_i (data_byte_count_i),
    .finalize_i        (finalize_i),
    .tag_valid_o       (tag_valid_o),
    .tag_match_o       (tag_match_o)
  );

endmodule
