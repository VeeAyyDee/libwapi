/* SPDX-License-Identifier: MPL-2.0 */
#include "internal.h"
#include "platform.h"

static const uint8_t initial_pn[16] = {0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c,0x36,0x5c};
static int check_addid(struct wapi_context *sm, const uint8_t *id)
{
    uint8_t bssid[6];
    (void)sm->callbacks->get_bssid(sm,bssid);
    return memcmp(bssid,id,6) || memcmp(sm->own_mac,id + 6,6) ? -1 : 0;
}
static int check_mic(struct wapi_context *sm, unsigned id, const uint8_t *data,
                      int length, const uint8_t *mic)
{
    if (id >= 2) return -1;
    esp_hmac_sha256_vector_t hmac = wapi_hmac_callback();
    if (!hmac) return -2;
    uint8_t digest[32];
    (void)hmac(sm->unicast[id] + 32,16,1,&data,&length,digest);
    return memcmp(digest,mic,20) ? -1 : 0;
}
static void make_mic(struct wapi_context *sm, unsigned id, const uint8_t *data,
                     int length, uint8_t *out)
{
    esp_hmac_sha256_vector_t hmac = wapi_hmac_callback();
    if (hmac) {
        uint8_t digest[32] = {0};
        (void)hmac(sm->unicast[id] + 32,16,1,&data,&length,digest);
        memcpy(out,digest,20);
    }
}
static void reply_header(struct wapi_context *sm, uint8_t *reply, uint16_t length, uint8_t subtype)
{
    sm->tx_sequence++;
    wapi_sm_set_header(reply,sm->tx_sequence,subtype);
    reply[6] = (uint8_t)(length >> 8); reply[7] = (uint8_t)length;
}
static int send_reply(struct wapi_context *sm, const uint8_t *reply, uint16_t length)
{
    uint8_t bssid[6];
    (void)sm->callbacks->get_bssid(sm,bssid);
    return sm->callbacks->ether_send(sm,bssid,0x88b4,reply,length) ? -1 : 0;
}
static int unicast_request(struct wapi_context *sm, const uint8_t *p, uint32_t length)
{
    static const uint8_t label[] = "pairwise key expansion for unicast and additional keys and nonce";
    if (sm->state >= 7 || !(0x6d & (1u << sm->state)) || length != 62) return -1;
    if (sm->key_management == 0x1000 || sm->key_management == 0x2000) {
        uint8_t addid[12];
        (void)sm->callbacks->get_bssid(sm,addid); memcpy(addid + 6,sm->own_mac,6);
        key_derivation_hmac_sha256(sm->base_key,16,addid,12,sm->base_key_id,16);
    }
    if (memcmp(sm->base_key_id,p + 1,16)) return -1;
    unsigned id = p[17];
    if (id > 1) return -2;
    if (check_addid(sm,p + 18)) return -3;
    if ((p[0] & 0x10) && sm->state != 0 && sm->state != 6) return -4;
    wapi_sm_asue_challenge(sm->station_challenge,32);
    memcpy(sm->ap_challenge,p + 30,32);
    sm->unicast_id = id; sm->pending_key_id = id & 1;
    uint8_t input[140];
    memcpy(input,p + 18,12); memcpy(input + 12,sm->ap_challenge,32);
    memcpy(input + 44,sm->station_challenge,32); memcpy(input + 76,label,64);
    key_derivation_hmac_sha256(sm->base_key,16,input,140,sm->unicast[id],96);
    sm->state = 6;
    uint8_t reply[150] = {0};
    reply_header(sm,reply,150,9);
    memcpy(reply + 12,p,30); memcpy(reply + 42,sm->station_challenge,32);
    memcpy(reply + 74,sm->ap_challenge,32);
    if (sm->assoc_ie_len) memcpy(reply + 106,sm->assoc_ie,sm->assoc_ie_len);
    make_mic(sm,id,reply + 12,118,reply + 130);
    return send_reply(sm,reply,150);
}
static int unicast_confirmation(struct wapi_context *sm, const uint8_t *p, uint32_t length)
{
    if (sm->state != 6 || length != 62 + sm->ap_ie_len + 20) return -1;
    unsigned id = p[17];
    if (memcmp(sm->base_key_id,p + 1,16) || id > 1 || check_addid(sm,p + 18) ||
        memcmp(sm->station_challenge,p + 30,32)) return -1;
    if (sm->ap_ie_len && memcmp(sm->ap_ie,p + 62,sm->ap_ie_len)) return -1;
    if (check_mic(sm,id,p,(int)(length - 20),p + length - 20)) return -1;
    uint8_t key[32], bssid[6];
    for (unsigned half = 0; half < 32; half += 16)
        for (unsigned i = 0; i < 16; ++i) key[half + i] = sm->unicast[sm->unicast_id][half + 15 - i];
    (void)sm->callbacks->get_bssid(sm,bssid);
    (void)sm->callbacks->set_key(sm,sm->pairwise_cipher == 0x400 ? 4 : 0,bssid,
        (int)sm->pending_key_id,1,initial_pn,16,key,32);
    sm->state = 0; sm->pending_key_id = 0;
    return 0;
}
static int multicast_announcement(struct wapi_context *sm, const uint8_t *p, uint32_t length)
{
    static const uint8_t label[] = "multicast or station key expansion for station unicast and multicast and broadcast";
    if (sm->state != 0 || length != 84) return -1;
    if (p[0] & 0x10) sm->multicast_rekey = 1;
    if ((p[0] & 0x20) || p[1] > 1 || p[2] > 1 || check_mic(sm,p[2],p,64,p + 64)) return -1;
    memcpy(sm->announcement_id,p + 31,16);
    if (p[47] != 16) return -1;
    sm->multicast_id = p[1];
    uint8_t secret[16]; memcpy(secret,p + 48,16);
    (void)wapi_sm_wpi_encrypt(sm->announcement_id,secret,16,sm->unicast[p[2]] + 48,secret);
    key_derivation_hmac_sha256(secret,16,label,82,sm->multicast_keys,32);
    uint8_t reply[63] = {0};
    reply_header(sm,reply,63,12);
    memcpy(reply + 12,p,15); memcpy(reply + 27,sm->announcement_id,16);
    make_mic(sm,sm->unicast_id,reply + 12,31,reply + 43);
    if (sm->multicast_rekey) {
        sm->multicast_rekey = 0; reply[42]++; sm->announcement_id[15]++;
    }
    return send_reply(sm,reply,63);
}
static void clear_fragments(struct wapi_context *sm)
{
    wapi_free(sm->fragment); sm->fragment = NULL; sm->fragment_len = 0;
    memset(sm->fragment_header,0,12);
}
static int valid_fragment(struct wapi_context *sm, const uint8_t *h, uint32_t length)
{
    const uint8_t *last = sm->fragment_header;
    /* Defined inputs have counts <=16384, avoiding the original signed-sum overflow. */
    return sm->fragment && h[10] == (unsigned)last[10] + 1 &&
        memcmp(h + 8,last + 8,2) == 0 && h[3] == last[3] &&
        (int64_t)(int32_t)sm->fragment_len + length <= 16384;
}
int wapi_process_packet_type(void *opaque, const uint8_t *header, uint16_t length)
{
    struct wapi_context *sm = opaque;
    if (wapi_sm_check_header(sm,header,NULL,length)) return -1;
    uint32_t payload_length = (uint16_t)((header[6] << 8 | header[7]) - 12);
    const uint8_t *payload = header + 12;
    uint16_t sequence = (uint16_t)(header[8] << 8 | header[9]);
    if (sm->fragment_header[11] && (sequence != sm->rx_sequence || header[10] == 0)) clear_fragments(sm);
    if (header[11] || sm->fragment_header[11]) {
        if (!sm->fragment && header[11]) {
            sm->fragment = wapi_malloc(16384);
            /* Original requires successful allocation and a fitting first fragment. */
            memcpy(sm->fragment,payload,payload_length);
            sm->fragment_len = payload_length;
            memcpy(sm->fragment_header,header,12);
            return 0;
        }
        if (!valid_fragment(sm,header,payload_length)) {
            sm->rx_sequence = 0; clear_fragments(sm); return -1;
        }
        memcpy(sm->fragment + sm->fragment_len,payload,payload_length);
        sm->fragment_len += payload_length;
        if (header[11]) { memcpy(sm->fragment_header,header,12); return 0; }
        payload = sm->fragment; payload_length = sm->fragment_len;
        memset(sm->fragment_header,0,12); sm->fragment_len = 0;
    }
    int status = 0;
    switch (header[3]) {
    case 8: status = unicast_request(sm,payload,payload_length); break;
    case 10: status = unicast_confirmation(sm,payload,payload_length); break;
    case 11: status = multicast_announcement(sm,payload,payload_length); break;
    case 2: status = -1; break;
    default: break;
    }
    if (sm->fragment) { wapi_free(sm->fragment); sm->fragment = NULL; }
    return status;
}
