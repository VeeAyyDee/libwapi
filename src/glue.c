/* SPDX-License-Identifier: MPL-2.0 */
#include "internal.h"
#include "platform.h"

static uint16_t little16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint16_t big16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static void put_big16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n; }
static uint32_t selector(const uint8_t *p, int akm)
{
    if (p[0] != 0 || p[1] != 0x14 || p[2] != 0x72) return 0;
    if (akm) {
        switch (p[3]) { case 0: return 0x10; case 1: return 0x2000; case 2: return 0x1000; default: return 0; }
    }
    return p[3] == 0 ? 1 : p[3] == 1 ? 0x400 : 0;
}
int wapi_sm_parse_wapi_ie(const uint8_t *ie, uint32_t length, void *parsed)
{
    uint32_t *p = parsed;
    const uint32_t defaults[7] = {4,0x400,0x400,0x1000,0,0,0};
    memcpy(p, defaults, sizeof defaults);
    if (length < 4 || ie[0] != 0x44 || ie[1] != length - 2 || little16(ie + 2) != 1) return -1;
    ie += 4; length -= 4;
    for (unsigned group = 0; group < 2; ++group) {
        if (!length) return 0;
        if (length < 2) return -1;
        uint32_t count = little16(ie);
        unsigned field = group == 0 ? 3 : 1;
        p[field] = 0;
        ie += 2; length -= 2;
        if (!count || count > length / 4) return -1;
        for (uint32_t i = 0; i < count; ++i) {
            p[field] |= selector(ie, group == 0);
            ie += 4; length -= 4;
        }
    }
    if (!length) return 0;
    if (length < 4) return -1;
    p[2] = selector(ie, 0); ie += 4; length -= 4;
    if (length >= 2) p[4] = little16(ie);
    return 0;
}
void wapi_neg_complete(void) { esp_wifi_auth_done_internal(); }
void wapi_supplicant_key_neg_complete(void *opaque, const uint8_t *bssid, int unused)
{
    struct wapi_context *sm = opaque;
    (void)bssid; (void)unused;
    sm->state = 0;
    wapi_neg_complete();
    sm->rx_sequence = sm->tx_sequence = 0;
}
static uint32_t *parameter(struct wapi_context *sm, uint32_t id)
{
    if (!sm) return NULL;
    switch (id) {
    case 0: return &sm->param0;
    case 1: return &sm->pairwise_cipher;
    case 2: return &sm->group_cipher;
    case 3: return &sm->key_management;
    default: return NULL;
    }
}
int wapi_sm_set_param(void *sm, uint32_t id, uint32_t value)
{
    if (!sm) return -1;
    uint32_t *p = parameter(sm, id);
    if (p) *p = value;
    return 0;
}
uint32_t wapi_sm_get_param(const void *sm, uint32_t id)
{
    const uint32_t *p = parameter((struct wapi_context *)sm, id);
    return p ? *p : 0;
}
int wapi_sm_set_assoc_wapi_ie_default(void *opaque, uint8_t *ie, uint32_t *capacity)
{
    struct wapi_context *sm = opaque;
    if (!sm || *capacity < 24) return -1;
    const uint8_t prefix[6] = {0x44,0,1,0,1,0};
    const uint8_t oui[3] = {0,0x14,0x72};
    memcpy(ie,prefix,6);
    if (sm->key_management != 0x1000 && sm->key_management != 0x2000) return -1;
    memcpy(ie + 6,oui,3); ie[9] = sm->key_management == 0x1000 ? 2 : 1;
    ie[10] = 1; ie[11] = 0;
    if (sm->pairwise_cipher != 0x400) return -1;
    memcpy(ie + 12,oui,3); ie[15] = 1;
    if (sm->group_cipher != 0x400) return -1;
    memcpy(ie + 16,oui,3); ie[19] = 1;
    memset(ie + 20,0,4);
    ie[1] = 22;
    *capacity = 24;
    if (sm->assoc_ie) return 0;
    sm->assoc_ie = wapi_malloc(24);
    if (!sm->assoc_ie) return -1;
    memcpy(sm->assoc_ie,ie,24); sm->assoc_ie_len = 24;
    return 0;
}
int wapi_sm_set_ap_wapi_ie(void *opaque, const uint8_t *ie, uint32_t length)
{
    struct wapi_context *sm = opaque;
    if (!sm) return -1;
    wapi_free(sm->ap_ie);
    if (!ie || !length) { sm->ap_ie = NULL; sm->ap_ie_len = 0; return 0; }
    sm->ap_ie = wapi_malloc(length);
    if (!sm->ap_ie) return -1;
    memcpy(sm->ap_ie,ie,length); sm->ap_ie_len = length;
    return 0;
}
uint8_t *wapi_sm_set_header(uint8_t *h, uint32_t sequence, uint8_t subtype)
{
    memset(h,0,12); h[1] = 1; h[2] = 1; h[3] = subtype;
    put_big16(h + 8,(uint16_t)sequence);
    return h + 12;
}
void wapi_sm_asue_challenge(uint8_t *out, uint32_t length) { (void)wapi_random(out,length); }
int wapi_sm_check_header(void *opaque, const uint8_t *h, const void *unused, uint16_t length)
{
    struct wapi_context *sm = opaque;
    (void)unused;
    if (length < 12 || big16(h) != 1 || h[2] != 1) return -1;
    if (h[3] < (sm->key_management == 0x1000 ? 8 : 3)) return -1;
    if (big16(h + 6) != length || big16(h + 8) < sm->rx_sequence) return -1;
    return 0;
}
void wapi_sm_set_own_addr(void *opaque, const uint8_t *mac)
{
    struct wapi_context *sm = opaque;
    memcpy(sm->own_mac,mac,6);
}
