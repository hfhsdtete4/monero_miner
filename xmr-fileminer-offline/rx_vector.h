/* rx_vector.h -- official RandomX test vector, embedded for self-checks.
 *
 * Source of truth: RandomX/src/tests/tests.cpp, "Hash test 1e"
 *   key     = "test key 001" (12 bytes, WITHOUT the trailing NUL: the RandomX
 *             test harness calls randomx_init_cache(cache, key, N - 1))
 *   input   = the 61 bytes encoded in RX_TEST_INPUT_HEX
 *   expected hash (standard RandomX, i.e. NOT the v2/Yada variant):
 *             c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1
 *
 * This vector passes identically in light mode and full-memory mode, and with
 * both the interpreter and the JIT. If a machine fails this check, its
 * RandomX hash results cannot be trusted and shares WILL be rejected -- so the
 * miner treats this as a hard gate.
 */
#ifndef RX_VECTOR_H
#define RX_VECTOR_H

#include <randomx.h>
#include <stdint.h>

/* This RandomX release has no public version macro; allow the build to inject
   one, otherwise report a neutral string. */
#ifndef RANDOMX_VERSION
#define RANDOMX_VERSION "librandomx"
#endif
#include <stdio.h>
#include <string.h>

static const char RX_TEST_KEY[] = "test key 001";
#define RX_TEST_KEY_LEN 12

static const char RX_TEST_INPUT_HEX[] =
    "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d2553"
    "7f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca6292"
    "76817b56f32e9b68bd82f416";

static const char RX_TEST_EXPECTED[] =
    "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1";

static int rx_hex_to_bin(const char *hex, uint8_t *out, size_t out_max, size_t *out_len)
{
    size_t n = 0;
    for (const char *p = hex; *p; ++p) {
        if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
            continue;
        if (n >= out_max * 2)
            return -1;
        int v;
        char c = *p;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return -1;
        if (n & 1)
            out[n >> 1] = (uint8_t)((out[n >> 1] & 0xF0) | (uint8_t)v);
        else
            out[n >> 1] = (uint8_t)(v << 4);
        ++n;
    }
    if (n & 1)
        return -1;
    *out_len = n >> 1;
    return 0;
}

static void rx_bin_to_hex(const uint8_t *bin, size_t len, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = hx[bin[i] >> 4];
        out[i * 2 + 1] = hx[bin[i] & 0xF];
    }
    out[len * 2] = '\0';
}

/* Returns 1 on pass. `got_hex` (optional) receives the computed hash hex. */
static int rx_selftest(randomx_vm *vm, char *got_hex, size_t got_sz)
{
    uint8_t input[128];
    uint8_t hash[64];
    size_t input_len = 0;
    if (rx_hex_to_bin(RX_TEST_INPUT_HEX, input, sizeof(input), &input_len) != 0)
        return -1;
    randomx_calculate_hash(vm, input, input_len, hash);
    if (got_hex && got_sz >= 65)
        rx_bin_to_hex(hash, 32, got_hex);
    uint8_t want[32];
    size_t want_len = 0;
    if (rx_hex_to_bin(RX_TEST_EXPECTED, want, sizeof(want), &want_len) != 0)
        return -1;
    return (want_len == 32 && memcmp(hash, want, 32) == 0) ? 1 : 0;
}

#endif /* RX_VECTOR_H */
