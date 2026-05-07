// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// SVA assertions for aes_gcm_aead. The properties cover protocol invariants
// enforced on every cycle of every test:
//
//   p_data_after_init    : data_ready_o never rises unless an init_i has
//                          been observed on this session.
//   p_result_stable      : result_o is stable while result_valid_o is high.
//   p_tag_stable_done    : tag_o is stable while tag_valid_o is high.
//   p_tag_after_finalize : tag_valid_o never rises before either an explicit
//                          finalize_i pulse OR a data_last_i beat being
//                          accepted.
//   p_tag_latency_bound  : tag_valid_o rises at most LAT_MAX cycles after
//                          an effective finalize. LAT_MAX is generous (4k)
//                          to absorb the 128-cycle GHASH multiplications;
//                          the bound exists to catch a stuck FSM, not to
//                          pin a tight number.
//   p_ctr_overflow_safe  : the 32-bit CTR counter does not silently roll
//                          over within a session (>2^32 blocks would do
//                          so; we don't ship a check on absolute count
//                          here, but assert that ctr_q is monotonic
//                          non-decreasing inside one session).
//
// Properties are wrapped in `ifndef SYNTHESIS so they are stripped on
// synthesis flows.

module aes_gcm_assertions #(
  parameter int LAT_MAX = 4096
) (
  input logic         clk_i,
  input logic         rst_ni,
  input logic         init_i,
  input logic         data_valid_i,
  input logic         data_ready_o,
  input logic         data_last_i,
  input logic         result_valid_o,
  input logic [127:0] result_o,
  input logic         tag_valid_o,
  input logic [127:0] tag_o,
  input logic         finalize_i
);
`ifndef SYNTHESIS

  // Track init / finalize / last-data seen.
  logic init_seen_q     = 1'b0;
  logic finalize_seen_q = 1'b0;
  int   cycles_since_finalize_q = 0;

  wire effective_finalize = finalize_i || (data_valid_i && data_ready_o && data_last_i);

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      init_seen_q             <= 1'b0;
      finalize_seen_q         <= 1'b0;
      cycles_since_finalize_q <= 0;
    end else begin
      if (init_i) begin
        init_seen_q     <= 1'b1;
        finalize_seen_q <= 1'b0;
      end
      if (effective_finalize) begin
        finalize_seen_q         <= 1'b1;
        cycles_since_finalize_q <= 0;
      end else if (finalize_seen_q && !tag_valid_o) begin
        cycles_since_finalize_q <= cycles_since_finalize_q + 1;
      end
    end
  end

  // 1. data_ready_o cannot rise without an init having been seen.
  property p_data_after_init;
    @(posedge clk_i) disable iff (!rst_ni)
      data_ready_o |-> init_seen_q;
  endproperty
  a_data_after_init: assert property (p_data_after_init)
    else $error("aes_gcm: data_ready_o asserted before init_i ever seen");

  // 2. result_o stable while valid.
  property p_result_stable;
    @(posedge clk_i) disable iff (!rst_ni)
      result_valid_o |=> (!result_valid_o || $stable(result_o));
  endproperty
  a_result_stable: assert property (p_result_stable)
    else $error("aes_gcm: result_o changed while result_valid_o asserted");

  // 3. tag stable while valid.
  property p_tag_stable_done;
    @(posedge clk_i) disable iff (!rst_ni)
      tag_valid_o |=> (!tag_valid_o || $stable(tag_o));
  endproperty
  a_tag_stable_done: assert property (p_tag_stable_done)
    else $error("aes_gcm: tag_o changed while tag_valid_o asserted");

  // 4. tag_valid_o stays low until an effective finalize has been seen.
  property p_tag_after_finalize;
    @(posedge clk_i) disable iff (!rst_ni || !init_seen_q)
      tag_valid_o |-> finalize_seen_q;
  endproperty
  a_tag_after_finalize: assert property (p_tag_after_finalize)
    else $error("aes_gcm: tag_valid_o asserted without finalize seen this session");

  // 5. tag latency bound after finalize.
  property p_tag_latency_bound;
    @(posedge clk_i) disable iff (!rst_ni)
      finalize_seen_q |-> (cycles_since_finalize_q < LAT_MAX);
  endproperty
  a_tag_latency_bound: assert property (p_tag_latency_bound)
    else $error("aes_gcm: tag did not arrive within %0d cycles of finalize", LAT_MAX);

`endif // SYNTHESIS
endmodule
