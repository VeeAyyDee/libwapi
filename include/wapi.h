/* SPDX-License-Identifier: MPL-2.0 */
#ifndef CLEAN_WAPI_H
#define CLEAN_WAPI_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
extern const uint8_t Sbox[256];
extern const uint32_t CK[32], FK[4];
extern const char *libwapi_reversion_git;
int wapi_sm_wpi_encrypt(const uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint8_t *);
int wapi_sm_wpi_decrypt(const uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint8_t *);
int wapi_sm_wpi_calc_mic(const uint8_t *, const uint8_t *, uint32_t, const uint8_t *, uint8_t *);
void wapi_neg_complete(void);
int wapi_sm_parse_wapi_ie(const uint8_t *, uint32_t, void *);
void wapi_supplicant_key_neg_complete(void *, const uint8_t *, int);
int wapi_sm_set_param(void *, uint32_t, uint32_t);
uint32_t wapi_sm_get_param(const void *, uint32_t);
int wapi_sm_set_assoc_wapi_ie_default(void *, uint8_t *, uint32_t *);
int wapi_sm_set_ap_wapi_ie(void *, const uint8_t *, uint32_t);
uint8_t *wapi_sm_set_header(uint8_t *, uint32_t, uint8_t);
void wapi_sm_asue_challenge(uint8_t *, uint32_t);
int wapi_sm_check_header(void *, const uint8_t *, const void *, uint16_t);
void wapi_txcb(void);
void key_derivation_hmac_sha256(const uint8_t *, int, const uint8_t *, int, uint8_t *, int);
int wapi_sm_deinit(void);
int esp_wifi_internal_wapi_deinit(void);
void wapi_sm_set_own_addr(void *, const uint8_t *);
int wapi_sm_init(void);
int esp_wifi_internal_wapi_init(void);
int wapi_process_packet_type(void *, const uint8_t *, uint16_t);
#ifdef __cplusplus
}
#endif
#endif
