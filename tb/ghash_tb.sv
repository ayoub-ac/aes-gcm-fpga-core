// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// Top-level testbench wrapper for the ghash_core multiplier. Stimulus
// from tb/sim_main_ghash.cpp.

module ghash_tb (
  input  logic         clk_i,
  input  logic         rst_ni,
  input  logic [127:0] y_i,
  input  logic [127:0] x_i,
  input  logic         start_i,
  output logic         ready_o,
  output logic [127:0] z_o,
  output logic         valid_o,
  input  logic         ack_i
);

  ghash_core u_dut (
    .clk_i  (clk_i),
    .rst_ni (rst_ni),
    .y_i    (y_i),
    .x_i    (x_i),
    .start_i(start_i),
    .ready_o(ready_o),
    .z_o    (z_o),
    .valid_o(valid_o),
    .ack_i  (ack_i)
  );

endmodule
