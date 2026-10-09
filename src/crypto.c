/* SPDX-License-Identifier: MPL-2.0 */
#include "wapi.h"
#include <string.h>

static uint32_t rotate(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}
static uint32_t read_word(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static void write_word(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24); p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8); p[3] = (uint8_t)x;
}
static uint32_t substitute(uint32_t x)
{
    return ((uint32_t)Sbox[x >> 24] << 24) |
           ((uint32_t)Sbox[(x >> 16) & 255] << 16) |
           ((uint32_t)Sbox[(x >> 8) & 255] << 8) | Sbox[x & 255];
}
static void expand_key(const uint8_t key[16], uint32_t rounds[32])
{
    uint32_t words[4];
    for (unsigned i = 0; i < 4; ++i) words[i] = read_word(key + i * 4) ^ FK[i];
    for (unsigned i = 0; i < 32; ++i) {
        uint32_t x = substitute(words[1] ^ words[2] ^ words[3] ^ CK[i]);
        uint32_t next = words[0] ^ x ^ rotate(x, 13) ^ rotate(x, 23);
        words[0] = words[1]; words[1] = words[2]; words[2] = words[3];
        words[3] = rounds[i] = next;
    }
}
static void transform(uint8_t block[16], const uint32_t rounds[32], int reverse)
{
    uint32_t words[4];
    for (unsigned i = 0; i < 4; ++i) words[i] = read_word(block + i * 4);
    for (unsigned i = 0; i < 32; ++i) {
        uint32_t x = substitute(words[1] ^ words[2] ^ words[3] ^ rounds[reverse ? 31 - i : i]);
        uint32_t next = words[0] ^ x ^ rotate(x, 2) ^ rotate(x, 10) ^ rotate(x, 18) ^ rotate(x, 24);
        words[0] = words[1]; words[1] = words[2]; words[2] = words[3]; words[3] = next;
    }
    for (unsigned i = 0; i < 4; ++i) write_word(block + i * 4, words[3 - i]);
}
static int crypt_feedback(const uint8_t *iv, const uint8_t *input, uint32_t length,
                          const uint8_t *key, uint8_t *output, int reverse)
{
    if (!length) return 1;
    uint32_t rounds[32];
    uint8_t feedback[16];
    expand_key(key, rounds);
    memcpy(feedback, iv, sizeof feedback);
    while (length) {
        unsigned count = length < 16 ? (unsigned)length : 16;
        transform(feedback, rounds, reverse);
        for (unsigned i = 0; i < count; ++i) output[i] = input[i] ^ feedback[i];
        input += count; output += count; length -= count;
    }
    return 0;
}
int wapi_sm_wpi_encrypt(const uint8_t *iv, const uint8_t *input, uint32_t length,
                         const uint8_t *key, uint8_t *output)
{
    return crypt_feedback(iv, input, length, key, output, 0);
}
int wapi_sm_wpi_decrypt(const uint8_t *iv, const uint8_t *input, uint32_t length,
                         const uint8_t *key, uint8_t *output)
{
    return crypt_feedback(iv, input, length, key, output, 1);
}
int wapi_sm_wpi_calc_mic(const uint8_t *iv, const uint8_t *input, uint32_t length,
                          const uint8_t *key, uint8_t *output)
{
    if (!length) return 1;
    uint32_t rounds[32];
    uint8_t accumulator[16];
    expand_key(key, rounds);
    memcpy(accumulator, iv, sizeof accumulator);
    transform(accumulator, rounds, 0);
    while (length) {
        unsigned count = length < 16 ? (unsigned)length : 16;
        for (unsigned i = 0; i < count; ++i) accumulator[i] ^= input[i];
        transform(accumulator, rounds, 0);
        input += count; length -= count;
    }
    memcpy(output, accumulator, 16);
    return 0;
}
