/*
 * SPDX-FileCopyrightText: 2017-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Excerpt: esp_wifi_crypto_types.h; original public SDK declaration. */
typedef int (*esp_hmac_sha256_vector_t)(const unsigned char *key, int key_len, int num_elem,
                                        const unsigned char *addr[], const int *len, unsigned char *mac);

/* Prefix excerpt from typedef struct wpa_crypto_funcs_t. Remaining fields omitted. */
/* Original complete type must be used in firmware; this is a documented prefix. */
/* uint32_t size;
 * uint32_t version;
 * esp_hmac_sha256_vector_t hmac_sha256_vector;
 */
