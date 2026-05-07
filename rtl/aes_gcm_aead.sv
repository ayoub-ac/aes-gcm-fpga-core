// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// AES-128-GCM AEAD top-level (NIST SP 800-38D).
//
// Construction:
//
//   H   = AES_K(0^128)                    // hash subkey
//   J0  = IV || 0^31 || 1                 // 96-bit IV path (the only one
//                                         //   we ship; SP 800-38D allows
//                                         //   other IV lengths but the
//                                         //   96-bit path is what TLS,
//                                         //   IPsec, MACsec, SSH all use)
//   E0  = AES_K(J0)                       // tag-mask block
//   ICB = inc32(J0)                       // initial counter block for CTR
//
//   For block i in 1..n:
//     Yi   = AES_K(inc32^(i-1)(ICB))      // keystream block
//     Ci   = Pi XOR Yi                    // CTR encrypt
//
//   GHASH input = AAD || pad0_to_16(AAD) || C || pad0_to_16(C)
//                  || len64(aad bits) || len64(ct bits)
//   S   = GHASH_H(input)
//   Tag = MSB_128 (S XOR E0)
//
// Mode select:
//   mode_i = 2'b00  ENCRYPT      ciphertext + tag
//   mode_i = 2'b01  DECRYPT      plaintext  + tag (caller checks)
//   mode_i = 2'b10  AAD_ONLY     no ct/pt, only authenticates AAD (rare)
//
// In our DECRYPT path the bytes presented on data_i are ciphertext; the
// XOR with the keystream produces plaintext on result_o. CRITICALLY, the
// GHASH absorbs the CIPHERTEXT regardless of direction (per SP 800-38D);
// in DECRYPT mode we therefore feed data_i (the input ciphertext) into
// GHASH, not result_o.
//
// Streaming protocol (mirrors the ChaCha20-Poly1305 sibling core):
//   1. Pulse init_i with key_i / nonce_i / mode_i.
//   2. Stream AAD as 16-byte chunks (last chunk's byte_count may be 1..16).
//      Skip entirely if aad_len = 0.
//   3. Stream PT/CT as 16-byte blocks. result_o is emitted in lock-step.
//      Mark the final block with data_last_i, OR pulse finalize_i after
//      the last data beat.
//   4. Wait for tag_valid_o; read tag_o and (optionally) tag_match_o.
//
// NONCE-REUSE WARNING: GCM with a repeated (key, IV) pair leaks the XOR
// of plaintexts AND lets an attacker recover H = AES_K(0^128), enabling
// arbitrary tag forgery. This module does NOT detect or prevent reuse.
// The integrator MUST guarantee uniqueness of every (key, IV).
//
// Endianness: byte 0 of every byte-stream lives in bits [127:120] (or
// [7:0] inside a 8-bit byte). That matches NIST SP 800-38D byte-string
// conventions and is what `cryptography.hazmat.primitives.ciphers.aead.
// AESGCM` produces on the wire.

module aes_gcm_aead (
  input  logic         clk_i,
  input  logic         rst_ni,

  // Session setup
  input  logic         init_i,
  input  logic [127:0] key_i,
  input  logic [95:0]  nonce_i,
  input  logic [1:0]   mode_i,
  output logic         init_ready_o,

  // AAD streaming (optional)
  input  logic         aad_valid_i,
  input  logic [127:0] aad_chunk_i,
  input  logic [4:0]   aad_byte_count_i,   // 1..16 (16 for full)
  input  logic         aad_last_i,
  output logic         aad_ready_o,

  // Plaintext / ciphertext streaming
  input  logic         data_valid_i,
  input  logic [127:0] data_i,             // 16-byte block
  input  logic [4:0]   data_byte_count_i,  // 1..16
  input  logic         data_last_i,
  output logic         data_ready_o,

  // Result streaming (encrypt: ct, decrypt: pt)
  output logic         result_valid_o,
  output logic [127:0] result_o,
  output logic [4:0]   result_byte_count_o,
  output logic         result_last_o,
  input  logic         result_ready_i,

  // Final tag
  input  logic         finalize_i,
  output logic [127:0] tag_o,
  output logic         tag_valid_o,

  // Decrypt-only convenience: caller sets expected_tag_i and we OR the
  // constant-time difference into tag_match_o.
  input  logic [127:0] expected_tag_i,
  output logic         tag_match_o
);

  localparam logic [1:0] M_ENCRYPT  = 2'b00;
  localparam logic [1:0] M_DECRYPT  = 2'b01;
  localparam logic [1:0] M_AAD_ONLY = 2'b10;

  // ------------------------------------------------------------------
  // Single AES-128 core, sequenced by the FSM. We use one shared AES
  // engine for: H derivation, E0 (tag mask) derivation, and per-block
  // CTR keystream. This is the area-cheap option (one core, ~12 cycles
  // per block). The Premium roadmap unrolls / pipelines this engine.
  // ------------------------------------------------------------------
  logic         aes_valid_i;
  logic         aes_ready_o;
  logic [127:0] aes_data_i;
  logic [127:0] aes_data_o;
  logic         aes_valid_o;
  logic         aes_ready_i;

  aes_core u_aes (
    .clk_i    (clk_i),
    .rst_ni   (rst_ni),
    .key_i    (sess_key_q),
    .data_i   (aes_data_i),
    .encrypt_i(1'b1),
    .valid_i  (aes_valid_i),
    .ready_o  (aes_ready_o),
    .data_o   (aes_data_o),
    .valid_o  (aes_valid_o),
    .ready_i  (aes_ready_i)
  );

  // ------------------------------------------------------------------
  // GHASH multiplier. We feed it (acc XOR block) and H, get back acc'.
  // ------------------------------------------------------------------
  logic         gh_start;
  logic         gh_ready;
  logic [127:0] gh_y;
  logic [127:0] gh_x;
  logic [127:0] gh_z;
  logic         gh_valid;
  logic         gh_ack;

  ghash_core u_gh (
    .clk_i  (clk_i),
    .rst_ni (rst_ni),
    .y_i    (gh_y),
    .x_i    (gh_x),
    .start_i(gh_start),
    .ready_o(gh_ready),
    .z_o    (gh_z),
    .valid_o(gh_valid),
    .ack_i  (gh_ack)
  );

  // ------------------------------------------------------------------
  // Session registers
  // ------------------------------------------------------------------
  logic [127:0] sess_key_q;
  logic [95:0]  sess_nonce_q;
  logic [1:0]   sess_mode_q;
  logic [127:0] H_q;            // hash subkey
  logic [127:0] E0_q;            // tag-mask block (AES(J0))
  logic [127:0] gh_acc_q;        // GHASH accumulator
  logic [31:0]  ctr_q;           // CTR counter (low 32 bits of the block)
  logic [63:0]  aad_bits_q;      // AAD length in bits
  logic [63:0]  ct_bits_q;       // ciphertext length in bits
  logic [127:0] result_q;
  logic [4:0]   result_bc_q;
  logic         result_last_q;
  logic         result_valid_q;
  logic [127:0] tag_q;
  logic         tag_valid_q;

  // J0 with 96-bit IV: nonce || 0x00000001
  // Block layout: bytes 0..11 = IV, bytes 12..15 = 0x00,0x00,0x00,0x01.
  // Big-endian register: byte 0 in [127:120], byte 15 in [7:0].
  // sess_nonce_q[95:0] holds bytes 0..11 with byte 0 in bits [95:88].
  logic [127:0] j0;
  assign j0 = {sess_nonce_q, 32'h0000_0001};

  // Counter block (current CTR input) = j0[127:32] || ctr_q. After we
  // see init we set ctr_q = 2 (J0 has counter=1 reserved for tag-mask
  // E0 derivation; CTR encryption uses counter 2, 3, ...).
  logic [127:0] ctr_block;
  assign ctr_block = {sess_nonce_q, ctr_q};

  // ------------------------------------------------------------------
  // Top-level FSM. Phases:
  //   T_IDLE        : waiting for init
  //   T_DERIVE_H    : run AES on 0^128 to get H
  //   T_DERIVE_E0   : run AES on J0 to get E0 (tag mask)
  //   T_AAD_RX      : receive an AAD chunk (or transition to data)
  //   T_AAD_GH      : feed (acc XOR aad_block) into GHASH multiply by H
  //   T_DATA_KS     : run AES on counter block to produce keystream
  //   T_DATA_XOR    : XOR keystream with data, present result, register
  //                   ciphertext for GHASH absorb
  //   T_DATA_GH     : feed (acc XOR ct_block) into GHASH multiply by H
  //   T_LEN_GH      : feed (acc XOR len-block) into GHASH (the trailing
  //                   length block per SP 800-38D)
  //   T_TAG         : tag = gh_acc_q XOR E0_q; assert tag_valid_o
  //   T_DONE        : sit and wait for next init
  // ------------------------------------------------------------------

  typedef enum logic [3:0] {
    T_IDLE       = 4'd0,
    T_DERIVE_H   = 4'd1,
    T_DERIVE_E0  = 4'd2,
    T_AAD_RX     = 4'd3,
    T_AAD_GH     = 4'd4,
    T_DATA_KS    = 4'd5,
    T_DATA_XOR   = 4'd6,
    T_DATA_GH    = 4'd7,
    T_LEN_GH     = 4'd8,
    T_TAG        = 4'd9,
    T_DONE       = 4'd10
  } tstate_e;

  tstate_e tstate_q, tstate_d;

  // Captured input data block for the current CTR/GHASH iteration.
  logic [127:0] data_buf_q;
  logic [4:0]   data_bc_q;
  logic         data_last_buf_q;
  logic         data_finalize_pending_q;  // saw finalize_i pulse

  // AAD chunk register (we may need to hold while GHASH runs).
  logic [127:0] aad_buf_q;
  logic [4:0]   aad_bc_q;
  logic         aad_last_buf_q;
  logic         aad_held_q;
  logic         aad_finalize_pending_q;   // set by finalize_i during AAD phase

  // After H derivation we hold AES.valid_o until we ack it; same for E0.
  // We capture into H_q / E0_q and ack in a single cycle.

  // Mask helpers
  function automatic logic [127:0] byte_mask128(input logic [4:0] bcb);
    if (bcb >= 5'd16) byte_mask128 = {128{1'b1}};
    else if (bcb == 5'd0) byte_mask128 = 128'd0;
    else byte_mask128 = ({{(127){1'b0}}, 1'b1} << (bcb * 8)) - 128'd1;
  endfunction

  // Big-endian byte-mask: byte 0 (bits [127:120]) is the most-significant
  // byte; we want the FIRST `bcb` bytes (byte 0..bcb-1) kept and the
  // remaining bytes zeroed. byte_mask128 above is little-endian-style
  // (keeps low bcb bytes). Reverse it byte-wise for big-endian:
  function automatic logic [127:0] be_byte_mask128(input logic [4:0] bcb);
    integer i;
    be_byte_mask128 = 128'd0;
    for (i = 0; i < 16; i = i + 1) begin
      if (i < bcb) be_byte_mask128[127 - 8*i -: 8] = 8'hff;
      else         be_byte_mask128[127 - 8*i -: 8] = 8'h00;
    end
  endfunction

  // Constant-time tag compare: XOR-OR-zero
  logic [127:0] tag_xor;
  assign tag_xor     = tag_q ^ expected_tag_i;
  assign tag_match_o = tag_valid_q && (tag_xor == 128'd0);

  // ------------------------------------------------------------------
  // Combinational FSM
  // ------------------------------------------------------------------
  logic [127:0] aad_masked;
  logic [127:0] data_masked;
  logic [127:0] keystream;
  logic [127:0] xor_result;
  logic [127:0] ct_for_ghash;        // CT block fed into GHASH (for absorb)

  assign keystream  = aes_data_o;
  assign xor_result = data_buf_q ^ keystream;
  assign aad_masked = aad_buf_q & be_byte_mask128(aad_bc_q);
  // Data masked: in encrypt we mask the XOR result (we emit ct, absorb ct);
  // in decrypt the data input IS ciphertext, so we mask data_buf_q for
  // GHASH and emit pt = data_buf_q XOR keystream (also masked).
  assign data_masked  = data_buf_q & be_byte_mask128(data_bc_q);
  assign ct_for_ghash = (sess_mode_q == M_DECRYPT)
                      ? data_masked
                      : (xor_result & be_byte_mask128(data_bc_q));

  always_comb begin
    tstate_d    = tstate_q;
    aes_valid_i = 1'b0;
    aes_data_i  = 128'd0;
    aes_ready_i = 1'b0;
    gh_start    = 1'b0;
    gh_ack      = 1'b0;
    gh_y        = gh_acc_q;
    gh_x        = H_q;

    case (tstate_q)
      // ----------------------------------------------------------------
      T_IDLE: begin
        if (init_i) tstate_d = T_DERIVE_H;
      end

      // ----------------------------------------------------------------
      T_DERIVE_H: begin
        if (aes_ready_o) begin
          aes_data_i  = 128'd0;
          aes_valid_i = 1'b1;
        end
        if (aes_valid_o) begin
          aes_ready_i = 1'b1;
          tstate_d    = T_DERIVE_E0;
        end
      end

      // ----------------------------------------------------------------
      T_DERIVE_E0: begin
        if (aes_ready_o) begin
          aes_data_i  = j0;
          aes_valid_i = 1'b1;
        end
        if (aes_valid_o) begin
          aes_ready_i = 1'b1;
          tstate_d    = T_AAD_RX;
        end
      end

      // ----------------------------------------------------------------
      T_AAD_RX: begin
        // Wait for an AAD chunk OR a transition signal (data_valid_i,
        // finalize_i, data_last_i).
        if (data_valid_i) begin
          tstate_d = T_DATA_KS;
        end else if (finalize_i) begin
          tstate_d = T_LEN_GH;
        end else if (aad_valid_i && aad_held_q == 1'b0) begin
          // Latch chunk happens in always_ff; transition to GH absorb.
          tstate_d = T_AAD_GH;
        end
      end

      // ----------------------------------------------------------------
      T_AAD_GH: begin
        if (gh_ready) begin
          gh_y     = gh_acc_q ^ aad_masked;
          gh_start = 1'b1;
        end
        if (gh_valid) begin
          gh_ack   = 1'b1;
          // After absorb: if this was the last AAD chunk, route based on
          // what's next (data or finalize).
          if (aad_last_buf_q && aad_finalize_pending_q) begin
            tstate_d = T_LEN_GH;
          end else if (aad_last_buf_q) begin
            tstate_d = T_AAD_RX;
          end else begin
            tstate_d = T_AAD_RX;
          end
        end
      end

      // ----------------------------------------------------------------
      T_DATA_KS: begin
        // Generate a keystream block by encrypting ctr_block.
        if (aes_ready_o) begin
          aes_data_i  = ctr_block;
          aes_valid_i = 1'b1;
        end
        if (aes_valid_o) begin
          aes_ready_i = 1'b1;
          tstate_d    = T_DATA_XOR;
        end
      end

      // ----------------------------------------------------------------
      T_DATA_XOR: begin
        // The result is xor_result (masked at output stage). Wait for the
        // consumer to take it, then start GHASH absorb.
        if (result_valid_q && result_ready_i) begin
          tstate_d = T_DATA_GH;
        end else if (!result_valid_q) begin
          // result not yet registered (waiting for clk), stay
          tstate_d = T_DATA_XOR;
        end
      end

      // ----------------------------------------------------------------
      T_DATA_GH: begin
        if (gh_ready) begin
          gh_y     = gh_acc_q ^ ct_for_ghash;
          gh_start = 1'b1;
        end
        if (gh_valid) begin
          gh_ack   = 1'b1;
          if (data_last_buf_q || data_finalize_pending_q) begin
            tstate_d = T_LEN_GH;
          end else begin
            tstate_d = T_DATA_KS;
          end
        end
      end

      // ----------------------------------------------------------------
      T_LEN_GH: begin
        // Build the trailing 16-byte block: len64(aad bits) || len64(ct bits)
        // big-endian (byte 0 = high byte of aad_bits_q).
        if (gh_ready) begin
          gh_y     = gh_acc_q ^ {aad_bits_q, ct_bits_q};
          gh_start = 1'b1;
        end
        if (gh_valid) begin
          gh_ack   = 1'b1;
          tstate_d = T_TAG;
        end
      end

      // ----------------------------------------------------------------
      T_TAG: begin
        // tag = gh_acc_q XOR E0_q. Latched in seq block; transition.
        tstate_d = T_DONE;
      end

      // ----------------------------------------------------------------
      T_DONE: begin
        if (init_i) tstate_d = T_DERIVE_H;
      end

      default: tstate_d = T_IDLE;
    endcase
  end

  // ------------------------------------------------------------------
  // Sequential
  // ------------------------------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      tstate_q                 <= T_IDLE;
      sess_key_q               <= 128'd0;
      sess_nonce_q             <= 96'd0;
      sess_mode_q              <= 2'b00;
      H_q                      <= 128'd0;
      E0_q                     <= 128'd0;
      gh_acc_q                 <= 128'd0;
      ctr_q                    <= 32'd0;
      aad_bits_q               <= 64'd0;
      ct_bits_q                <= 64'd0;
      result_q                 <= 128'd0;
      result_bc_q              <= 5'd0;
      result_last_q            <= 1'b0;
      result_valid_q           <= 1'b0;
      tag_q                    <= 128'd0;
      tag_valid_q              <= 1'b0;
      data_buf_q               <= 128'd0;
      data_bc_q                <= 5'd0;
      data_last_buf_q          <= 1'b0;
      data_finalize_pending_q  <= 1'b0;
      aad_buf_q                <= 128'd0;
      aad_bc_q                 <= 5'd0;
      aad_last_buf_q           <= 1'b0;
      aad_held_q               <= 1'b0;
      aad_finalize_pending_q   <= 1'b0;
    end else begin
      tstate_q <= tstate_d;

      // Latch session on init
      if (init_i) begin
        sess_key_q              <= key_i;
        sess_nonce_q            <= nonce_i;
        sess_mode_q             <= mode_i;
        gh_acc_q                <= 128'd0;
        // CTR for the FIRST data block is inc32(J0) = J0 with counter=2.
        // (J0 itself uses counter=1; that block is the tag mask E0.)
        ctr_q                   <= 32'd2;
        aad_bits_q              <= 64'd0;
        ct_bits_q               <= 64'd0;
        result_valid_q          <= 1'b0;
        tag_valid_q             <= 1'b0;
        tag_q                   <= 128'd0;
        data_finalize_pending_q <= 1'b0;
        aad_finalize_pending_q  <= 1'b0;
        aad_held_q              <= 1'b0;
        data_last_buf_q         <= 1'b0;
      end

      // Capture H from AES output in T_DERIVE_H
      if (tstate_q == T_DERIVE_H && aes_valid_o) H_q <= aes_data_o;

      // Capture E0 in T_DERIVE_E0
      if (tstate_q == T_DERIVE_E0 && aes_valid_o) E0_q <= aes_data_o;

      // Capture AAD chunk on accept (handshake: aad_valid_i && aad_ready_o)
      if (tstate_q == T_AAD_RX && aad_valid_i && aad_ready_o) begin
        aad_buf_q              <= aad_chunk_i;
        aad_bc_q               <= aad_byte_count_i;
        aad_last_buf_q         <= aad_last_i;
        aad_held_q             <= 1'b1;
        aad_bits_q             <= aad_bits_q + ({59'd0, aad_byte_count_i} << 3);
      end

      // Track finalize pulse during AAD phase (if no data_valid arrives).
      if (tstate_q == T_AAD_RX && finalize_i && !aad_valid_i) begin
        aad_finalize_pending_q <= 1'b1;
      end

      // Clear aad_held when GHASH absorbs the chunk
      if (tstate_q == T_AAD_GH && gh_valid) begin
        aad_held_q <= 1'b0;
      end

      // Capture data block on accept
      if (tstate_q == T_AAD_RX && data_valid_i) begin
        data_buf_q              <= data_i;
        data_bc_q               <= data_byte_count_i;
        data_last_buf_q         <= data_last_i;
        ct_bits_q               <= ct_bits_q + ({59'd0, data_byte_count_i} << 3);
      end

      // While in T_DATA_GH, if a new data beat arrives we accept it ONCE
      // GHASH is done. Easier: accept the next data block at T_DATA_KS
      // entry. But we want continuous flow; we accept on transition out
      // of T_DATA_GH back to T_DATA_KS via the data_ready_o handshake.
      if (tstate_q == T_DATA_GH && tstate_d == T_DATA_KS &&
          data_valid_i && data_ready_o) begin
        data_buf_q              <= data_i;
        data_bc_q               <= data_byte_count_i;
        data_last_buf_q         <= data_last_i;
        ct_bits_q               <= ct_bits_q + ({59'd0, data_byte_count_i} << 3);
      end

      // Track finalize during DATA phases
      if ((tstate_q == T_DATA_KS || tstate_q == T_DATA_XOR ||
           tstate_q == T_DATA_GH) && finalize_i) begin
        data_finalize_pending_q <= 1'b1;
      end

      // CTR increment after each AES keystream consumption
      if (tstate_q == T_DATA_KS && aes_valid_o) begin
        ctr_q <= ctr_q + 32'd1;
      end

      // Result register: produce on the cycle we have keystream + data.
      // We register the result so the consumer can read it across cycles
      // while the absorb is running.
      if (tstate_q == T_DATA_KS && aes_valid_o) begin
        result_q       <= xor_result & be_byte_mask128(data_bc_q);
        result_bc_q    <= data_bc_q;
        result_last_q  <= data_last_buf_q;
        result_valid_q <= 1'b1;
      end
      if (result_valid_q && result_ready_i) begin
        result_valid_q <= 1'b0;
      end

      // Latch GHASH accumulator
      if ((tstate_q == T_AAD_GH || tstate_q == T_DATA_GH ||
           tstate_q == T_LEN_GH) && gh_valid) begin
        gh_acc_q <= gh_z;
      end

      // Compute tag
      if (tstate_q == T_TAG) begin
        tag_q       <= gh_acc_q ^ E0_q;
        tag_valid_q <= 1'b1;
      end
    end
  end

  // ------------------------------------------------------------------
  // External handshake outputs
  // ------------------------------------------------------------------
  assign init_ready_o = (tstate_q == T_IDLE) || (tstate_q == T_DONE);
  assign aad_ready_o  = (tstate_q == T_AAD_RX) && !aad_held_q;
  assign data_ready_o = (tstate_q == T_AAD_RX) ||
                        (tstate_q == T_DATA_GH && gh_valid);

  assign result_valid_o      = result_valid_q;
  assign result_o            = result_q;
  assign result_byte_count_o = result_bc_q;
  assign result_last_o       = result_last_q;

  assign tag_o       = tag_q;
  assign tag_valid_o = tag_valid_q;

endmodule
