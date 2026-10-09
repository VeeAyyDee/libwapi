/* SPDX-License-Identifier: MPL-2.0 */
#include "internal.h"
#include "platform.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static void *os_slots[128];
void **g_osi_funcs_p = os_slots;
static unsigned allocations, frees, fail_at, live, auth_calls, install_calls, sends;
static uint8_t sent[256], installed[32];
static uint16_t sent_length;
static int send_result;
static void *registered;
static struct wapi_context *allocated_context;
static unsigned deauth_calls;
struct driver_table {
    int (*receive)(void *, const uint8_t *, uint32_t);
    int (*parse_ie)(const uint8_t *, uint8_t, void *);
    int (*association_ie)(uint8_t *);
    int (*ap_ie)(const uint8_t *, uint32_t);
    void (*set_bssid)(const uint8_t *);
    void (*notify_assoc)(void);
    void (*derive_base_key)(const char *, int);
};
static void *allocate(size_t n)
{
    if (++allocations == fail_at) return NULL;
    void *p = malloc(n); assert(p); ++live; return p;
}
static void *allocate_zero(size_t n)
{
    void *p = allocate(n);
    if (p) memset(p,0,n);
    if (n == sizeof(struct wapi_context)) allocated_context = p;
    return p;
}
static void release(void *p) { ++frees; if (p) { assert(live); --live; free(p); } }
static int random_bytes(uint8_t *p, size_t n) { for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)(i + 0x60); return -1; }
/* Deliberately simple test digest: this tests vector framing and callback flow,
 * not SHA-256 itself, which is supplied by the SDK. */
static int digest(const uint8_t *key, int key_len, int count, const uint8_t *data[], const int *lengths, uint8_t *out)
{
    assert(count == 1);
    uint32_t sum = 17;
    for (int i = 0; i < key_len; ++i) sum = sum * 33u + key[i];
    for (int i = 0; i < lengths[0]; ++i) sum = sum * 33u + data[0][i];
    for (unsigned i = 0; i < 32; ++i) { sum = sum * 1664525u + 1013904223u; out[i] = (uint8_t)(sum >> 24); }
    return -17; /* The implementation must ignore the callback status. */
}
/* Definition mirrors the SDK's two uint32_t prefix fields and native callback. */
struct crypto_table { uint32_t size, version; esp_hmac_sha256_vector_t hmac; };
/* platform.h declares an opaque byte symbol; use an assembler name for this typed definition. */
const struct crypto_table test_crypto_table __asm__("wpa_crypto_funcs") = {sizeof(struct crypto_table),1,digest};
void esp_wifi_auth_done_internal(void) { ++auth_calls; }
int esp_wifi_deauthenticate_internal(int reason) { assert(reason == 1); ++deauth_calls; return 0; }
int esp_wifi_sta_is_running_internal(void) { return 1; }
int wifi_get_macaddr(int index, uint8_t *out) { assert(index == 0); memset(out,0x42,6); return 0; }
int ieee80211_register_wapi_cb(void *table) { registered = table; return -3; }
int ieee80211_unregister_wapi_cb(void) { release(registered); registered = NULL; return 7; }
int ic_register_tx_cb(void (*cb)(void), int type, int enabled) { assert(cb == wapi_txcb && type == 16 && enabled == 1); return -1; }
int ieee80211_output(int index, const uint8_t *frame, uint16_t n) { assert(index == 0 && n >= 14 && frame[12] == 0x88 && frame[13] == 0xb4); return -1; }
int ppInstallKey(int a, const uint8_t *p, int id, int tx, const uint8_t *pn, int pn_len, const uint8_t *key, int key_len, int slot)
{
    (void)a; (void)p; (void)id; (void)slot; assert(tx == 1 && pn_len == 16 && key_len == 32);
    for (int i = 0; i < 16; ++i) assert(pn[i] == (i % 2 ? 0x5c : 0x36));
    memcpy(installed,key,32); ++install_calls; return -9;
}
int hexstr2bin(const char *s, uint8_t *out, size_t n) { (void)s; memset(out,0,n); return -1; }
static int get_bssid(void *opaque, uint8_t *out) { memcpy(out,((struct wapi_context *)opaque)->bssid,6); return 0; }
static int install(void *opaque, int a, const uint8_t *p, int id, int tx, const uint8_t *pn, int pn_len, const uint8_t *key, int key_len)
{ (void)opaque; return ppInstallKey(a,p,id,tx,pn,pn_len,key,key_len,4); }
static int send_packet(void *opaque, const uint8_t *dest, uint16_t type, const uint8_t *packet, uint16_t n)
{
    (void)opaque; (void)dest; assert(type == 0x88b4 && n <= sizeof sent);
    memcpy(sent,packet,n); sent_length = n; ++sends; return send_result;
}
static void header(uint8_t *p, uint16_t n, unsigned sequence, uint8_t subtype)
{ memset(p,0,n); wapi_sm_set_header(p,sequence,subtype); p[6] = (uint8_t)(n >> 8); p[7] = (uint8_t)n; }
static void mic(const uint8_t *key, uint8_t *p, int n) { uint8_t out[32]; const uint8_t *data = p; digest(key,16,1,&data,&n,out); memcpy(p + n,out,20); }
static void test_parser(void)
{
    uint8_t ie[32] = {0x44,2,1,0}; uint32_t p[7];
    assert(wapi_sm_parse_wapi_ie(ie,4,p) == 0 && p[0] == 4 && p[3] == 0x1000);
    for (unsigned n = 0; n < 4; ++n) assert(wapi_sm_parse_wapi_ie(ie,n,p) == -1 && p[1] == 0x400);
    ie[1] = 8; ie[4] = 1; ie[6] = 0; ie[7] = 0x14; ie[8] = 0x72; ie[9] = 1;
    assert(wapi_sm_parse_wapi_ie(ie,10,p) == 0 && p[3] == 0x2000);
    ie[9] = 42; assert(wapi_sm_parse_wapi_ie(ie,10,p) == 0 && p[3] == 0);
    ie[4] = 2; assert(wapi_sm_parse_wapi_ie(ie,10,p) == -1 && p[3] == 0);
}
static void test_lifetime(void)
{
    assert(wapi_sm_deinit() == -1);
    for (unsigned i = 1; i <= 3; ++i) {
        allocations = 0; fail_at = i;
        assert(wapi_sm_init() == -(int)i && live == 0 && !registered);
    }
    allocations = 0; fail_at = 0;
    assert(esp_wifi_internal_wapi_init() == 0 && live == 3 && registered);
    assert(esp_wifi_internal_wapi_deinit() == 7 && live == 0 && !registered);
}
static void test_association_failure_residue(void)
{
    struct wapi_context sm = {0};
    uint8_t ie[32];
    for (unsigned invalid_field = 0; invalid_field < 3; ++invalid_field) {
        sm.key_management = invalid_field == 0 ? 0 : 0x1000;
        sm.pairwise_cipher = invalid_field == 1 ? 0 : 0x400;
        sm.group_cipher = invalid_field == 2 ? 0 : 0x400;
        memset(ie,0xa5,sizeof ie); uint32_t capacity = 32;
        unsigned allocations_before = allocations;
        assert(wapi_sm_set_assoc_wapi_ie_default(&sm,ie,&capacity) == -1);
        const uint8_t prefix[6] = {0x44,0,1,0,1,0};
        assert(!memcmp(ie,prefix,6) && capacity == 32 && !sm.assoc_ie);
        assert(allocations == allocations_before);
        unsigned untouched = invalid_field == 0 ? 6 : invalid_field == 1 ? 12 : 16;
        assert(ie[untouched] == 0xa5);
    }
    sm.key_management = 0x1000; sm.pairwise_cipher = sm.group_cipher = 0x400;
    uint32_t capacity = 32;
    assert(wapi_sm_set_assoc_wapi_ie_default(&sm,ie,&capacity) == 0);
    assert(ie[1] == 22 && capacity == 24 && sm.assoc_ie[1] == 22);
    release(sm.assoc_ie);
}
static void test_registered_callbacks(void)
{
    assert(wapi_sm_init() == 0);
    struct wapi_context *sm = allocated_context;
    struct driver_table *driver = registered;
    assert(sm->state == 1 && sm->own_mac[0] == 0x42);
    uint8_t bssid[6] = {1,2,3,4,5,6}; driver->set_bssid(bssid);
    assert(memcmp(sm->bssid,bssid,6) == 0);
    driver->derive_base_key("test passphrase",0); assert(sm->state == 2);
    driver->notify_assoc(); assert(sm->state == 3);
    uint8_t ie[24] = {0x44,22,1,0,1,0,0,0x14,0x72,2,1,0,0,0x14,0x72,1,0,0x14,0x72,1,0,0,0,0};
    uint32_t parsed[7];
    assert(driver->parse_ie(ie,24,parsed) == 0 && sm->key_management == 0x1000);
    uint8_t out[32]; assert(driver->association_ie(out) == 24 && !memcmp(out,ie,24));
    assert(driver->ap_ie(ie,24) == 0);
    uint8_t packet[32]; header(packet,28,2,9); sm->rx_sequence = 40;
    assert(driver->receive(NULL,packet,28) == 0 && sm->rx_sequence == 2);
    assert(driver->receive(NULL,packet,29) == -1 && deauth_calls == 1);
    sm->tx_sequence = 8;
    for (unsigned i = 0; i < 32; ++i) sm->multicast_keys[i] = (uint8_t)i;
    wapi_txcb(); assert(sm->state == 0 && sm->rx_sequence == 0 && sm->tx_sequence == 0);
    assert(sm->driver_slot == sm->multicast_id && sm->multicast_keys[0] == 15 && sm->multicast_keys[16] == 31);
    wapi_txcb(); assert(sm->multicast_keys[0] == 0 && sm->multicast_keys[16] == 16);
    assert(wapi_sm_deinit() == 7 && live == 0);
    install_calls = auth_calls = 0;
}
static void test_expansion(void)
{
    const uint8_t key[3] = {1,2,3}, text[4] = {4,5,6,7};
    const uint8_t *data = text; int n = 4;
    uint8_t expected[96], out[97];
    digest(key,3,1,&data,&n,expected);
    data = expected; n = 32; digest(key,3,1,&data,&n,expected + 32);
    data = expected + 32; digest(key,3,1,&data,&n,expected + 64);
    for (int length = 0; length <= 96; ++length) {
        memset(out,0xa5,sizeof out);
        key_derivation_hmac_sha256(key,3,text,4,out,length);
        assert(!memcmp(out,expected,(size_t)length) && out[length] == 0xa5);
    }
}
static void test_exchange(void)
{
    struct wapi_callbacks callbacks = {NULL,install,get_bssid,send_packet};
    struct wapi_context sm = {0}; sm.callbacks = &callbacks;
    sm.state = 2; sm.key_management = 0x1000; sm.pairwise_cipher = sm.group_cipher = 0x400;
    memset(sm.own_mac,0x11,6); memset(sm.bssid,0x22,6);
    uint8_t ie[32]; uint32_t cap = 32;
    assert(wapi_sm_set_assoc_wapi_ie_default(&sm,ie,&cap) == 0 && cap == 24 && sm.assoc_ie_len == 24);
    assert(wapi_sm_set_ap_wapi_ie(&sm,ie,24) == 0);
    uint8_t packet[128], addid[12]; memcpy(addid,sm.bssid,6); memcpy(addid + 6,sm.own_mac,6);
    header(packet,74,1,8); uint8_t *p = packet + 12;
    key_derivation_hmac_sha256(sm.base_key,16,addid,12,p + 1,16);
    p[17] = 1; memcpy(p + 18,addid,12); memset(p + 30,0x33,32);
    assert(wapi_process_packet_type(&sm,packet,74) == 0);
    assert(sm.state == 6 && sm.unicast_id == 1 && sm.pending_key_id == 1 && sm.tx_sequence == 1);
    assert(sent_length == 150 && sent[3] == 9 && !memcmp(sent + 106,ie,24));
    assert(!memcmp(sent + 42,sm.station_challenge,32) && !memcmp(sent + 74,sm.ap_challenge,32));
    header(packet,118,2,10); p = packet + 12;
    memcpy(p + 1,sm.base_key_id,16); p[17] = 1; memcpy(p + 18,addid,12);
    memcpy(p + 30,sm.station_challenge,32); memcpy(p + 62,ie,24);
    mic(sm.unicast[1] + 32,p,86);
    packet[117] ^= 1; assert(wapi_process_packet_type(&sm,packet,118) == -1 && sm.state == 6);
    packet[117] ^= 1; assert(wapi_process_packet_type(&sm,packet,118) == 0 && sm.state == 0 && sm.pending_key_id == 0);
    assert(install_calls == 1 && auth_calls == 0);
    for (unsigned i = 0; i < 32; ++i) assert(installed[i] == sm.unicast[1][(i & 16) + 15 - (i & 15)]);
    header(packet,96,3,11); p = packet + 12;
    p[0] = 0x10; p[1] = 1; p[2] = 1; memcpy(p + 3,addid,12); memset(p + 31,0x55,16); p[47] = 16;
    memset(p + 48,0x66,16); mic(sm.unicast[1] + 32,p,64);
    send_result = -2;
    assert(wapi_process_packet_type(&sm,packet,96) == -1);
    assert(sm.state == 0 && sm.multicast_id == 1 && sm.tx_sequence == 2 && sm.multicast_rekey == 0);
    assert(sent_length == 63 && sent[42] == 0x56 && sm.announcement_id[15] == 0x56);
    send_result = 0;
    uint8_t digest_out[32]; const uint8_t *data = sent + 12; int n = 31;
    digest(sm.unicast[1] + 32,16,1,&data,&n,digest_out);
    assert(memcmp(digest_out,sent + 43,20) != 0); /* Compatibility: increment follows MIC. */
    sm.rx_sequence = 0;
    header(packet,20,4,9); packet[11] = 1;
    assert(wapi_process_packet_type(&sm,packet,20) == 0 && sm.fragment_len == 8);
    sm.rx_sequence = 4; packet[10] = 1; packet[11] = 0;
    assert(wapi_process_packet_type(&sm,packet,20) == 0 && !sm.fragment && sm.fragment_len == 0);
    packet[10] = 0; packet[11] = 1;
    assert(wapi_process_packet_type(&sm,packet,20) == 0);
    packet[10] = 2;
    assert(wapi_process_packet_type(&sm,packet,20) == -1 && !sm.fragment && sm.rx_sequence == 0);
    sm.rx_sequence = 7; assert(wapi_sm_check_header(&sm,packet,NULL,20) == -1);
    sm.state = 6; sm.tx_sequence = 2;
    wapi_supplicant_key_neg_complete(&sm,sm.bssid,0);
    assert(sm.state == 0 && !sm.rx_sequence && !sm.tx_sequence && auth_calls == 1);
    uint32_t prior_length = sm.ap_ie_len;
    fail_at = allocations + 1;
    assert(wapi_sm_set_ap_wapi_ie(&sm,ie,3) == -1 && !sm.ap_ie && sm.ap_ie_len == prior_length);
    fail_at = 0; release(sm.assoc_ie);
    assert(live == 0);
}
int main(void)
{
    os_slots[0xb0 / 4] = (void *)release; os_slots[0x168 / 4] = (void *)allocate;
    os_slots[0x174 / 4] = (void *)allocate_zero; os_slots[0x13c / 4] = (void *)random_bytes;
    test_parser(); test_expansion(); test_association_failure_residue(); test_lifetime(); test_registered_callbacks(); test_exchange();
    assert(wapi_sm_set_param(NULL,0,1) == -1 && wapi_sm_get_param(NULL,0) == 0);
    printf("parser, allocation unwind, lifecycle, key exchange, MIC, mutation residue and fragmentation checks passed (%u frees)\n",frees);
    return 0;
}
