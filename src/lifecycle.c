/* SPDX-License-Identifier: MPL-2.0 */
#include "internal.h"
#include "platform.h"

static struct wapi_context *wapi_global;
struct driver_callbacks {
    int (*receive)(void *, const uint8_t *, uint32_t);
    int (*parse_ie)(const uint8_t *, uint8_t, void *);
    int (*association_ie)(uint8_t *);
    int (*ap_ie)(const uint8_t *, uint32_t);
    void (*set_bssid)(const uint8_t *);
    void (*notify_assoc)(void);
    void (*derive_base_key)(const char *, int);
};
#if UINTPTR_MAX == UINT32_MAX
_Static_assert(sizeof(struct driver_callbacks) == 28, "driver callback ABI size");
#endif
static const uint8_t broadcast[6] = {255,255,255,255,255,255};
static const uint8_t initial_pn[16] = {0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c};
static int get_bssid(void *opaque, uint8_t *out)
{
    struct wapi_context *sm = opaque;
    if (!sm || !out) return -1;
    memcpy(out,sm->bssid,6); return 0;
}
static int set_key(void *opaque, int algorithm, const uint8_t *peer, int id,
                   int tx, const uint8_t *sequence, int sequence_len,
                   const uint8_t *key, int key_len)
{
    struct wapi_context *sm = opaque;
    sm->driver_slot = memcmp(peer,broadcast,6) == 0 ? (uint8_t)id : 4;
    return ppInstallKey(algorithm,peer,id,tx,sequence,sequence_len,key,key_len,sm->driver_slot);
}
static int ether_send(void *opaque, const uint8_t *dest, uint16_t type,
                      const uint8_t *payload, uint16_t length)
{
    struct wapi_context *sm = opaque;
    uint8_t *frame = wapi_malloc((size_t)length + 14);
    if (!frame) return -2;
    memcpy(frame,dest,6); memcpy(frame + 6,sm->own_mac,6);
    frame[12] = (uint8_t)(type >> 8); frame[13] = (uint8_t)type;
    memcpy(frame + 14,payload,length);
    (void)ieee80211_output(0,frame,(uint16_t)(length + 14));
    wapi_free(frame); return 0;
}
void key_derivation_hmac_sha256(const uint8_t *key, int key_len,
                                const uint8_t *text, int text_len,
                                uint8_t *output, int length)
{
    esp_hmac_sha256_vector_t hmac = wapi_hmac_callback();
    if (length <= 0 || !hmac) return; /* Original missing-callback partial output is undefined. */
    uint8_t digest[32], previous[32];
    const uint8_t *input = text;
    int input_len = text_len;
    while (length > 0) {
        (void)hmac(key,key_len,1,&input,&input_len,digest);
        int count = length < 32 ? length : 32;
        memcpy(output,digest,(size_t)count);
        output += count; length -= count;
        memcpy(previous,digest,32); input = previous; input_len = 32;
    }
}
static void set_bssid(const uint8_t *mac)
{
    if (wapi_global && mac) memcpy(wapi_global->bssid,mac,6);
}
static void notify_assoc(void) { if (wapi_global) wapi_global->state = 3; }
static int parse_ie(const uint8_t *ie, uint8_t length, void *parsed)
{
    if (!parsed) return -1;
    int status = wapi_sm_parse_wapi_ie(ie,length,parsed);
    if (!status && wapi_global) {
        uint32_t *fields = parsed;
        wapi_sm_set_param(wapi_global,3,fields[3]);
        wapi_sm_set_param(wapi_global,1,fields[1]);
        wapi_sm_set_param(wapi_global,2,fields[2]);
    }
    return status;
}
static int association_ie(uint8_t *out)
{
    uint32_t capacity = 32;
    if (!out || wapi_sm_set_assoc_wapi_ie_default(wapi_global,out,&capacity)) return 0;
    (void)ic_register_tx_cb(wapi_txcb,16,1); return 24;
}
static int ap_ie(const uint8_t *ie, uint32_t length)
{
    return wapi_sm_set_ap_wapi_ie(wapi_global,ie,length);
}
static void derive_base_key(const char *text, int is_hex)
{
    static const uint8_t label[] = "preshared key expansion for authentication and key negotiation";
    if (!wapi_global) return;
    size_t length = strlen(text);
    if (is_hex) {
        uint8_t decoded[128] = {0};
        /* Compatibility discrepancy: vendor call uses character count here. */
        (void)hexstr2bin(text,decoded,length);
        key_derivation_hmac_sha256(decoded,(int)(length / 2),label,62,wapi_global->base_key,16);
    } else {
        key_derivation_hmac_sha256((const uint8_t *)text,(int)length,label,62,wapi_global->base_key,16);
    }
    wapi_global->state = 2;
}
static int receive(void *unused, const uint8_t *packet, uint32_t length)
{
    (void)unused;
    struct wapi_context *sm = wapi_global;
    int status = -1;
    /* As in the original ABI, a live context and readable header are preconditions. */
    uint16_t encoded = (uint16_t)(packet[6] << 8 | packet[7]);
    if ((sm->key_management == 0x1000 || sm->key_management == 0x2000) && length > 27 && length >= encoded) {
        sm->rx_sequence = (uint16_t)(packet[8] << 8 | packet[9]);
        status = wapi_process_packet_type(sm,packet,(uint16_t)length);
    }
    if (status && sm->state >= 3) (void)esp_wifi_deauthenticate_internal(1);
    return status;
}
int wapi_sm_init(void)
{
    struct driver_callbacks *driver = wapi_zalloc(sizeof *driver);
    if (!driver) return -1;
    struct wapi_context *sm = wapi_zalloc(sizeof *sm);
    if (!sm) { wapi_free(driver); return -2; }
    sm->callbacks = wapi_zalloc(sizeof *sm->callbacks);
    if (!sm->callbacks) { wapi_free(driver); wapi_free(sm); return -3; }
    sm->callbacks->set_key = set_key; sm->callbacks->get_bssid = get_bssid;
    sm->callbacks->ether_send = ether_send;
    driver->receive = receive; driver->parse_ie = parse_ie;
    driver->association_ie = association_ie; driver->ap_ie = ap_ie;
    driver->set_bssid = set_bssid; driver->notify_assoc = notify_assoc;
    driver->derive_base_key = derive_base_key;
    (void)wifi_get_macaddr(0,sm->own_mac); sm->state = 1;
    wapi_global = sm;
    (void)ieee80211_register_wapi_cb(driver);
    return 0;
}
int wapi_sm_deinit(void)
{
    struct wapi_context *sm = wapi_global;
    if (!sm) return -1;
    wapi_free(sm->assoc_ie); wapi_free(sm->ap_ie); wapi_free(sm->callbacks);
    wapi_free(sm->fragment); wapi_free(sm); wapi_global = NULL;
    return ieee80211_unregister_wapi_cb();
}
int esp_wifi_internal_wapi_init(void) { return wapi_sm_init(); }
int esp_wifi_internal_wapi_deinit(void) { return wapi_sm_deinit(); }
void wapi_txcb(void)
{
    struct wapi_context *sm = wapi_global;
    if (!esp_wifi_sta_is_running_internal()) return;
    uint8_t bssid[6];
    (void)sm->callbacks->get_bssid(sm,bssid);
    for (unsigned half = 0; half < 32; half += 16) {
        for (unsigned i = 0; i < 8; ++i) {
            uint8_t byte = sm->multicast_keys[half + i];
            sm->multicast_keys[half + i] = sm->multicast_keys[half + 15 - i];
            sm->multicast_keys[half + 15 - i] = byte;
        }
    }
    (void)sm->callbacks->set_key(sm,sm->group_cipher == 0x400 ? 4 : 0,broadcast,
        (int)sm->multicast_id,1,initial_pn,16,sm->multicast_keys,32);
    wapi_supplicant_key_neg_complete(sm,bssid,0);
}
