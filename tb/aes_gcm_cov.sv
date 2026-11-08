// SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Commercial
//
// Functional coverage collector for aes_gcm_aead. Sticky bins recorded
// across the regression so the harness can print a single coverage line
// at end-of-test.
//
// Bins (10 total):
//   c_mode_encrypt   : init_i seen with mode_i == ENCRYPT
//   c_mode_decrypt   : init_i seen with mode_i == DECRYPT
//   c_mode_aad_only  : init_i seen with mode_i == AAD_ONLY
//   c_aad_seen       : at least one AAD chunk consumed
//   c_data_short     : a finalised session whose plaintext fit in <=16 B
//   c_data_long      : a finalised session whose plaintext exceeded 16 B
//   c_partial_last   : data_last_i seen with byte_count < 16
//   c_full_last      : data_last_i seen with byte_count == 16
//   c_finalize_seen  : finalize_i pulsed
//   c_tag_emitted    : tag_valid_o pulsed at least once
//   c_tag_mismatch   : at least one session ended with tag_match_o low
//                      (tampered-tag exercise)

module aes_gcm_cov (
  input logic         clk_i,
  input logic         rst_ni,
  input logic         init_i,
  input logic [1:0]   mode_i,
  input logic         aad_valid_i,
  input logic         aad_ready_o,
  input logic         data_valid_i,
  input logic         data_ready_o,
  input logic         data_last_i,
  input logic [4:0]   data_byte_count_i,
  input logic         finalize_i,
  input logic         tag_valid_o,
  input logic         tag_match_o
);

  logic c_mode_encrypt   /*verilator public*/;
  logic c_mode_decrypt   /*verilator public*/;
  logic c_mode_aad_only  /*verilator public*/;
  logic c_aad_seen       /*verilator public*/;
  logic c_data_short     /*verilator public*/;
  logic c_data_long      /*verilator public*/;
  logic c_partial_last   /*verilator public*/;
  logic c_full_last      /*verilator public*/;
  logic c_finalize_seen  /*verilator public*/;
  logic c_tag_emitted    /*verilator public*/;
  logic c_tag_mismatch   /*verilator public*/;

  // Track total data bytes per session.
  logic [31:0] data_bytes_q;
  logic        match_seen_q;

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      data_bytes_q <= 32'd0;
      match_seen_q <= 1'b0;
    end else begin
      if (init_i) begin
        data_bytes_q <= 32'd0;
        match_seen_q <= 1'b0;
        if (mode_i == 2'b00) c_mode_encrypt   <= 1'b1;
        if (mode_i == 2'b01) c_mode_decrypt   <= 1'b1;
        if (mode_i == 2'b10) c_mode_aad_only  <= 1'b1;
      end

      if (aad_valid_i && aad_ready_o) c_aad_seen <= 1'b1;

      if (data_valid_i && data_ready_o) begin
        data_bytes_q <= data_bytes_q + {27'd0, data_byte_count_i};
        if (data_last_i) begin
          if (data_byte_count_i == 5'd16) c_full_last    <= 1'b1;
          else                            c_partial_last <= 1'b1;
        end
      end

      if (finalize_i) c_finalize_seen <= 1'b1;
      if (tag_valid_o) begin
        c_tag_emitted <= 1'b1;
        if (!tag_match_o) c_tag_mismatch <= 1'b1;
      end

      if (finalize_i ||
          (data_valid_i && data_ready_o && data_last_i)) begin
        logic [31:0] total;
        total = data_bytes_q;
        if (data_valid_i && data_ready_o && data_last_i)
          total = total + {27'd0, data_byte_count_i};
        if (total <= 32'd16) c_data_short <= 1'b1;
        else                 c_data_long  <= 1'b1;
      end
    end
  end

  initial begin
    c_mode_encrypt   = 1'b0;
    c_mode_decrypt   = 1'b0;
    c_mode_aad_only  = 1'b0;
    c_aad_seen       = 1'b0;
    c_data_short     = 1'b0;
    c_data_long      = 1'b0;
    c_partial_last   = 1'b0;
    c_full_last      = 1'b0;
    c_finalize_seen  = 1'b0;
    c_tag_emitted    = 1'b0;
    c_tag_mismatch   = 1'b0;
  end

endmodule
