/* SPDX-License-Identifier: MPL-2.0 */
#ifndef CLEAN_WAPI_INTERNAL_H
#define CLEAN_WAPI_INTERNAL_H
#include "wapi.h"
#include <stddef.h>
#include <string.h>
struct wapi_context;
struct wapi_callbacks {
    void *reserved;
    int (*set_key)(void *, int, const uint8_t *, int, int, const uint8_t *, int, const uint8_t *, int);
    int (*get_bssid)(void *, uint8_t *);
    int (*ether_send)(void *, const uint8_t *, uint16_t, const uint8_t *, uint16_t);
};
struct wapi_context {
    struct wapi_callbacks *callbacks;
    uint32_t state, param0;
    uint8_t unicast[2][96], own_mac[6], bssid[6];
    uint32_t unicast_id, multicast_id;
    uint8_t station_challenge[32], ap_challenge[32];
    uint8_t *assoc_ie;
    uint32_t assoc_ie_len;
    uint8_t *ap_ie;
    uint32_t ap_ie_len;
    uint8_t base_key[16], base_key_id[16], multicast_keys[32];
    uint16_t rx_sequence, tx_sequence;
    uint32_t pairwise_cipher, group_cipher, key_management, pending_key_id;
    uint8_t driver_slot, multicast_rekey, announcement_id[16], padding[2];
    uint8_t *fragment;
    uint32_t fragment_len;
    uint8_t fragment_header[12];
};
#if UINTPTR_MAX == UINT32_MAX
#define WAPI_OFFSET(field, value) _Static_assert(offsetof(struct wapi_context, field) == value, #field " ABI")
WAPI_OFFSET(callbacks, 0x000); WAPI_OFFSET(state, 0x004); WAPI_OFFSET(param0, 0x008);
WAPI_OFFSET(unicast, 0x00c); WAPI_OFFSET(own_mac, 0x0cc); WAPI_OFFSET(bssid, 0x0d2);
WAPI_OFFSET(unicast_id, 0x0d8); WAPI_OFFSET(multicast_id, 0x0dc);
WAPI_OFFSET(station_challenge, 0x0e0); WAPI_OFFSET(ap_challenge, 0x100);
WAPI_OFFSET(assoc_ie, 0x120); WAPI_OFFSET(assoc_ie_len, 0x124);
WAPI_OFFSET(ap_ie, 0x128); WAPI_OFFSET(ap_ie_len, 0x12c);
WAPI_OFFSET(base_key, 0x130); WAPI_OFFSET(base_key_id, 0x140); WAPI_OFFSET(multicast_keys, 0x150);
WAPI_OFFSET(rx_sequence, 0x170); WAPI_OFFSET(tx_sequence, 0x172);
WAPI_OFFSET(pairwise_cipher, 0x174); WAPI_OFFSET(group_cipher, 0x178);
WAPI_OFFSET(key_management, 0x17c); WAPI_OFFSET(pending_key_id, 0x180);
WAPI_OFFSET(driver_slot, 0x184); WAPI_OFFSET(multicast_rekey, 0x185);
WAPI_OFFSET(announcement_id, 0x186); WAPI_OFFSET(fragment, 0x198);
WAPI_OFFSET(fragment_len, 0x19c); WAPI_OFFSET(fragment_header, 0x1a0);
_Static_assert(sizeof(struct wapi_context) == 428, "context ABI size");
_Static_assert(sizeof(struct wapi_callbacks) == 16, "callback ABI size");
#undef WAPI_OFFSET
#endif
#endif
