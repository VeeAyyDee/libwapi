/* SPDX-License-Identifier: MPL-2.0 */
#ifndef CLEAN_WAPI_PLATFORM_H
#define CLEAN_WAPI_PLATFORM_H
#include <stddef.h>
#include <stdint.h>
/* Target table uses 32-bit pointer slots. Native tests provide the same slot
 * indices with native-width pointers, without claiming native ABI parity. */
extern void **g_osi_funcs_p;
extern void esp_wifi_auth_done_internal(void);
extern int esp_wifi_deauthenticate_internal(int);
extern int esp_wifi_sta_is_running_internal(void);
extern int wifi_get_macaddr(int, uint8_t *);
extern int ieee80211_register_wapi_cb(void *);
extern int ieee80211_unregister_wapi_cb(void);
extern int ic_register_tx_cb(void (*)(void), int, int);
extern int ieee80211_output(int, const uint8_t *, uint16_t);
extern int ppInstallKey(int, const uint8_t *, int, int, const uint8_t *, int, const uint8_t *, int, int);
extern int hexstr2bin(const char *, uint8_t *, size_t);
static inline void wapi_free(void *p)
{
    ((void (*)(void *))g_osi_funcs_p[0xb0 / 4])(p);
}
static inline void *wapi_malloc(size_t n)
{
    return ((void *(*)(size_t))g_osi_funcs_p[0x168 / 4])(n);
}
static inline void *wapi_zalloc(size_t n)
{
    return ((void *(*)(size_t))g_osi_funcs_p[0x174 / 4])(n);
}
static inline int wapi_random(uint8_t *out, size_t n)
{
    return ((int (*)(uint8_t *, size_t))g_osi_funcs_p[0x13c / 4])(out, n);
}
#include "../spec/public-sdk/crypto-declaration.h"
extern const unsigned char wpa_crypto_funcs[];
static inline esp_hmac_sha256_vector_t wapi_hmac_callback(void)
{
    esp_hmac_sha256_vector_t callback;
    /* The SDK crypto table has an eight-byte fixed prefix on both builds. */
    __builtin_memcpy(&callback, wpa_crypto_funcs + 8, sizeof callback);
    return callback;
}
#endif
