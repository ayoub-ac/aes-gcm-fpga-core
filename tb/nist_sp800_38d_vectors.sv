// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
//
// NIST SP 800-38D Appendix B published AES-128-GCM test vectors.
// Reproduced here in SystemVerilog macro form for consumption by
// non-Verilator simulators (Vivado xsim / ModelSim / Questa). The
// Verilator harness reads the same vectors directly from sim_main.cpp.
//
// This file lists the four published Appendix B test cases that use a
// 96-bit IV:
//   * Test Case 1: empty K, P, A
//   * Test Case 2: K=0, P=0^128, A=empty (one zero block)
//   * Test Case 3: real K/IV, P=4 blocks (64 B), A=empty
//   * Test Case 4: real K/IV, P=60 B (3 full blocks + 12 B), A=20 B
//
// Test Cases 5 and 6 of Appendix B use 8-byte and 60-byte IVs
// respectively. Variable-length IV is on the Premium roadmap (it
// requires a separate GHASH-based J0 derivation step). They are
// covered in the C++ random-vector harness via the Python
// `cryptography` reference for the 96-bit-IV path only.

`ifndef NIST_SP800_38D_VECTORS_SV
`define NIST_SP800_38D_VECTORS_SV

// ---------------- Test Case 1 ------------------------------------------
//   K = 00000000000000000000000000000000
//   IV = 000000000000000000000000
//   P = (empty), A = (empty)
//   Tag = 58e2fccefa7e3061367f1d57a4e7455a
`define NIST_TC1_KEY     128'h0000_0000_0000_0000_0000_0000_0000_0000
`define NIST_TC1_IV       96'h0000_0000_0000_0000_0000_0000
`define NIST_TC1_TAG     128'h58e2_fcce_fa7e_3061_367f_1d57_a4e7_455a

// ---------------- Test Case 2 ------------------------------------------
//   K = 00000000000000000000000000000000
//   IV = 000000000000000000000000
//   P = 00000000000000000000000000000000  (one zero block)
//   A = empty
//   CT = 0388dace60b6a392f328c2b971b2fe78
//   Tag = ab6e47d42cec13bdf53a67b21257bddf
`define NIST_TC2_KEY     128'h0000_0000_0000_0000_0000_0000_0000_0000
`define NIST_TC2_IV       96'h0000_0000_0000_0000_0000_0000
`define NIST_TC2_PT      128'h0000_0000_0000_0000_0000_0000_0000_0000
`define NIST_TC2_CT      128'h0388_dace_60b6_a392_f328_c2b9_71b2_fe78
`define NIST_TC2_TAG     128'hab6e_47d4_2cec_13bd_f53a_67b2_1257_bddf

// ---------------- Test Case 3 ------------------------------------------
//   K  = feffe9928665731c6d6a8f9467308308
//   IV = cafebabefacedbaddecaf888
//   P  = d9313225f88406e5a55909c5aff5269a
//        86a7a9531534f7da2e4c303d8a318a72
//        1c3c0c95956809532fcf0e2449a6b525
//        b16aedf5aa0de657ba637b391aafd255   (4 blocks, 64 bytes)
//   A = empty
//   CT = 42831ec2217774244b7221b784d0d49c
//        e3aa212f2c02a4e035c17e2329aca12e
//        21d514b25466931c7d8f6a5aac84aa05
//        1ba30b396a0aac973d58e091473f5985
//   Tag = 4d5c2af327cd64a62cf35abd2ba6fab4
`define NIST_TC3_KEY     128'hfeff_e992_8665_731c_6d6a_8f94_6730_8308
`define NIST_TC3_IV       96'hcafe_babe_face_dbad_deca_f888
`define NIST_TC3_TAG     128'h4d5c_2af3_27cd_64a6_2cf3_5abd_2ba6_fab4

// ---------------- Test Case 4 ------------------------------------------
//   K  = feffe9928665731c6d6a8f9467308308
//   IV = cafebabefacedbaddecaf888
//   P  = d9313225f88406e5a55909c5aff5269a
//        86a7a9531534f7da2e4c303d8a318a72
//        1c3c0c95956809532fcf0e2449a6b525
//        b16aedf5aa0de657ba637b39           (60 bytes = 3 full + 12)
//   A  = feedfacedeadbeeffeedfacedeadbeef
//        abaddad2                           (20 bytes = 1 full + 4)
//   CT = 42831ec2217774244b7221b784d0d49c
//        e3aa212f2c02a4e035c17e2329aca12e
//        21d514b25466931c7d8f6a5aac84aa05
//        1ba30b396a0aac973d58e091
//   Tag = 5bc94fbc3221a5db94fae95ae7121a47
`define NIST_TC4_KEY     128'hfeff_e992_8665_731c_6d6a_8f94_6730_8308
`define NIST_TC4_IV       96'hcafe_babe_face_dbad_deca_f888
`define NIST_TC4_TAG     128'h5bc9_4fbc_3221_a5db_94fa_e95a_e712_1a47

`endif
