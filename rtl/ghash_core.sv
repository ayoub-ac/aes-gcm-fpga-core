// SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Commercial
//
// GHASH core (NIST SP 800-38D, sec 6.4).
//
// Computes Y = GHASH(H, X) over GF(2^128) with reduction polynomial
//   p(x) = x^128 + x^7 + x^2 + x + 1
// using the "shift-and-add" / "schoolbook" iterative algorithm. One
// 128-bit multiplication takes 128 cycles. A typical AES-GCM session
// performs M = ceil(aad_len/16) + ceil(ct_len/16) + 1 multiplications,
// where the +1 is the trailing length block (len64(aad) || len64(ct)).
//
// NIST uses the "right-shift" GF(2^128) convention. Block bytes are
// laid out with byte 0 (most significant in the polynomial sense)
// occupying bits [127:120] of the 128-bit register. Bit 127 of the
// register is therefore the highest-order coefficient (x^127), and
// bit 0 is the lowest (x^0). The reduction constant R is
//   R = e1 || 00 || ... || 00 = 128'hE100_..._0000
// which sits in bits [127:120] of the register.
//
// Algorithm (Algorithm 1 in SP 800-38D, equivalent form):
//   z = 0
//   v = y
//   for i = 0..127:                       // i indexes bits of x from
//       if x[127 - i] = 1: z = z ^ v       //   bit 127 (leftmost in NIST
//       if v[0] = 1: v = (v >> 1) ^ R      //   notation) down to bit 0
//       else       : v = (v >> 1)
//   return z
//
// Equivalent reformulation used here (drives v from y once at start_i,
// shifts one bit per cycle):
//   on start: z <= 0, v <= y, x_q <= x, idx <= 127
//   each cycle: if x_q[idx]: z <= z ^ v
//               v <= (v[0] ? ((v >> 1) ^ R) : (v >> 1))
//               idx <= idx - 1
//
// To accumulate over a stream of blocks the caller does:
//   y0 = 0
//   for each block X_i: y_{i+1} = (y_i XOR X_i) * H mod p
// i.e. they XOR the next block into the accumulator (input port `y_i`)
// and call `start_i` with `x_i` set to H. This module is the inner
// multiplier; the AEAD top wraps it into an absorber.
//
// Handshake:
//   * Caller presents y_i, x_i (== H) and pulses start_i for one cycle
//     while ready_o is high.
//   * Core captures, drops ready_o, runs 128 cycles, asserts valid_o
//     with z_o stable.
//   * Caller asserts ack_i for one cycle to release; ready_o re-asserts
//     on the next cycle.
//
// Reset: rst_ni is active-low synchronous (sampled on rising clk_i).

module ghash_core (
  input  logic         clk_i,
  input  logic         rst_ni,
  input  logic [127:0] y_i,           // accumulator input (left operand)
  input  logic [127:0] x_i,           // hash subkey H (right operand)
  input  logic         start_i,
  output logic         ready_o,
  output logic [127:0] z_o,           // y_i * x_i mod p
  output logic         valid_o,
  input  logic         ack_i
);

  // Reduction constant R = 0xE1 || 0^120 (top byte 0xE1).
  localparam logic [127:0] R = {8'hE1, 120'd0};

  typedef enum logic [1:0] {
    G_IDLE = 2'd0,
    G_RUN  = 2'd1,
    G_DONE = 2'd2
  } gstate_e;

  gstate_e      state_q, state_d;
  logic [127:0] z_q, z_d;
  logic [127:0] v_q, v_d;
  logic [127:0] x_q, x_d;
  logic [6:0]   idx_q, idx_d;     // counts 127 down to 0

  // ---------- Combinational next-state ---------------------------------
  always_comb begin
    state_d = state_q;
    z_d     = z_q;
    v_d     = v_q;
    x_d     = x_q;
    idx_d   = idx_q;

    unique case (state_q)
      G_IDLE: begin
        if (start_i) begin
          z_d     = 128'd0;
          v_d     = y_i;
          x_d     = x_i;
          idx_d   = 7'd127;
          state_d = G_RUN;
        end
      end

      G_RUN: begin
        // Conditional add of v into z when current bit of x is 1.
        // x_q[idx_q] is the (127 - idx_q)-th bit from the leftmost in the
        // NIST convention; idx_q starts at 127, so we walk x's bits MSB
        // first as the algorithm prescribes (x[127] -> v[127] in NIST
        // numbering corresponds to x_q[127] -> v before any shift).
        // Storage convention: register bit 127 is the high-order term.
        if (x_q[idx_q]) z_d = z_q ^ v_q;
        else            z_d = z_q;
        v_d = v_q[0] ? ((v_q >> 1) ^ R) : (v_q >> 1);
        if (idx_q == 7'd0) state_d = G_DONE;
        else               idx_d   = idx_q - 7'd1;
      end

      G_DONE: begin
        if (ack_i) state_d = G_IDLE;
      end

      default: state_d = G_IDLE;
    endcase
  end

  // ---------- Sequential ----------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      state_q <= G_IDLE;
      z_q     <= 128'd0;
      v_q     <= 128'd0;
      x_q     <= 128'd0;
      idx_q   <= 7'd0;
    end else begin
      state_q <= state_d;
      z_q     <= z_d;
      v_q     <= v_d;
      x_q     <= x_d;
      idx_q   <= idx_d;
    end
  end

  // ---------- Outputs --------------------------------------------------
  assign ready_o = (state_q == G_IDLE);
  assign valid_o = (state_q == G_DONE);
  assign z_o     = z_q;

endmodule
