// SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Commercial
//
// Verilator C++ unit harness for ghash_core. Tests the GF(2^128) multiplier
// in isolation against a software reference (NIST SP 800-38D Algorithm 1)
// over 50 random pairs.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>

#include "verilated.h"
#include "Vghash_tb.h"

static int g_failures = 0;
static vluint64_t g_time = 0;

static void tick(Vghash_tb* dut) {
    dut->clk_i = 0; dut->eval(); g_time++;
    dut->clk_i = 1; dut->eval(); g_time++;
}
static void reset(Vghash_tb* dut) {
    dut->rst_ni = 0;
    dut->start_i = 0;
    dut->ack_i = 0;
    for (int i = 0; i < 4; i++) dut->y_i[i] = 0;
    for (int i = 0; i < 4; i++) dut->x_i[i] = 0;
    for (int i = 0; i < 4; i++) tick(dut);
    dut->rst_ni = 1;
    tick(dut);
}

// ---------------------------------------------------------------------------
// 128-bit operand carrier (low/high 64 bits) plus serialisation helpers.
// "Big-endian" wire order: bit 127 of the polynomial = bit 7 of byte 0.
// ---------------------------------------------------------------------------
struct U128 {
    uint64_t lo, hi;
};
static U128 from_bytes(const uint8_t b[16]) {
    U128 x;
    x.hi = ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8 ) | ((uint64_t)b[7]);
    x.lo = ((uint64_t)b[8] << 56) | ((uint64_t)b[9] << 48) |
           ((uint64_t)b[10] << 40) | ((uint64_t)b[11] << 32) |
           ((uint64_t)b[12] << 24) | ((uint64_t)b[13] << 16) |
           ((uint64_t)b[14] << 8 ) | ((uint64_t)b[15]);
    return x;
}
static void to_bytes(U128 x, uint8_t out[16]) {
    for (int i = 0; i < 8; i++) {
        out[i]    = (x.hi >> (56 - 8*i)) & 0xff;
        out[8+i]  = (x.lo >> (56 - 8*i)) & 0xff;
    }
}

// Software reference: NIST SP 800-38D §6.4 Algorithm 1.
static U128 gf128_mul(U128 a, U128 b) {
    U128 z = {0, 0};
    U128 v = b;
    // Walk x's bits from leftmost (bit 127 = a.hi MSB) down to bit 0
    // (a.lo LSB).
    for (int i = 0; i < 128; i++) {
        bool bit;
        if (i < 64) bit = (a.hi >> (63 - i)) & 1;
        else        bit = (a.lo >> (63 - (i - 64))) & 1;
        if (bit) {
            z.lo ^= v.lo;
            z.hi ^= v.hi;
        }
        bool lsb = v.lo & 1;
        // Shift right by 1: lo gets v.hi LSB shifted in as MSB, hi shifts down.
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi = (v.hi >> 1);
        if (lsb) {
            v.hi ^= 0xE100000000000000ULL;
        }
    }
    return z;
}

static void put_bus(uint32_t* dst, U128 x) {
    // dst is 4 little-endian 32-bit words representing a 128-bit value
    // where dst[3] is the most-significant 32-bit word.
    dst[3] = (uint32_t)(x.hi >> 32);
    dst[2] = (uint32_t)(x.hi & 0xffffffffULL);
    dst[1] = (uint32_t)(x.lo >> 32);
    dst[0] = (uint32_t)(x.lo & 0xffffffffULL);
}
static U128 get_bus(const uint32_t* src) {
    U128 x;
    x.hi = ((uint64_t)src[3] << 32) | (uint64_t)src[2];
    x.lo = ((uint64_t)src[1] << 32) | (uint64_t)src[0];
    return x;
}

static U128 do_mul(Vghash_tb* dut, U128 a, U128 b) {
    int waited = 0;
    while (!dut->ready_o) {
        tick(dut);
        if (++waited > 500) { g_failures++; return {0, 0}; }
    }
    put_bus(&dut->y_i[0], a);
    put_bus(&dut->x_i[0], b);
    dut->start_i = 1;
    tick(dut);
    dut->start_i = 0;
    waited = 0;
    while (!dut->valid_o) {
        tick(dut);
        if (++waited > 500) { g_failures++; return {0, 0}; }
    }
    U128 z = get_bus(&dut->z_o[0]);
    dut->ack_i = 1;
    tick(dut);
    dut->ack_i = 0;
    return z;
}

int main(int argc, char** argv) {
    Verilated::commandArgs(argc, argv);
    setvbuf(stdout, nullptr, _IOLBF, 0);
    Vghash_tb* dut = new Vghash_tb();
    reset(dut);

    std::printf("---- ghash_core: 50 random pair multiplies ----\n");
    srand(0xCA117E5);
    int passes = 0;
    for (int i = 0; i < 50; i++) {
        U128 a, b;
        a.hi = ((uint64_t)rand() << 32) | (uint32_t)rand();
        a.lo = ((uint64_t)rand() << 32) | (uint32_t)rand();
        b.hi = ((uint64_t)rand() << 32) | (uint32_t)rand();
        b.lo = ((uint64_t)rand() << 32) | (uint32_t)rand();
        U128 ref = gf128_mul(a, b);
        U128 got = do_mul(dut, a, b);
        if (ref.hi == got.hi && ref.lo == got.lo) {
            passes++;
        } else {
            if (passes + (50 - passes - 1) - i < 3) {
                std::printf("  [FAIL] #%d\n    a   = %016lx %016lx\n"
                            "    b   = %016lx %016lx\n"
                            "    exp = %016lx %016lx\n"
                            "    got = %016lx %016lx\n",
                            i, (unsigned long)a.hi, (unsigned long)a.lo,
                            (unsigned long)b.hi, (unsigned long)b.lo,
                            (unsigned long)ref.hi, (unsigned long)ref.lo,
                            (unsigned long)got.hi, (unsigned long)got.lo);
            }
            g_failures++;
        }
    }
    std::printf("  random: %d / 50 pass\n", passes);

    if (g_failures == 0) {
        std::printf("+PASS ghash random tests passed\n");
        delete dut;
        return 0;
    } else {
        std::printf("+FAIL %d failures\n", g_failures);
        delete dut;
        return 1;
    }
}
