# Export ABI and primitive behavior

Signatures below are inferred functional ABI declarations, independently expressed; only the two `esp_wifi_internal_*` prototypes are published in the pinned SDK. `const` qualifiers express observed access and do not alter ABI. A source implementation may use opaque types with the stated layout.

| Export | Functional signature | Behavior |
|---|---|---|
| wapi_sm_wpi_encrypt | int (const uint8_t *iv, const uint8_t *input, uint32_t length, const uint8_t *key, uint8_t *output) | SM4 OFB as described below |
| wapi_sm_wpi_decrypt | same | OFB-like mode with reverse round keys, as described below |
| wapi_sm_wpi_calc_mic | same | writes a 16-byte MIC |
| wapi_neg_complete | void (void) | invokes esp_wifi_auth_done_internal() |
| wapi_sm_parse_wapi_ie | int (const uint8_t *ie, uint32_t length, void *parsed) | parsed output is seven 32-bit words |
| wapi_supplicant_key_neg_complete | void (void *sm, const uint8_t *bssid, int unused) | logs negotiated ciphers, sets state 0; invokes auth-done; then clears BOTH 16-bit sequence counters |
| wapi_sm_set_param | int (void *sm, uint32_t id, uint32_t value) | NULL returns -1; otherwise sets IDs 0..3, unknown ID does nothing and returns 0 |
| wapi_sm_get_param | uint32_t (const void *sm, uint32_t id) | NULL/unknown ID returns 0 |
| wapi_sm_set_assoc_wapi_ie_default | int (void *sm, uint8_t *ie, uint32_t *capacity_length) | emits association IE and may retain owned copy |
| wapi_sm_set_ap_wapi_ie | int (void *sm, const uint8_t *ie, uint32_t length) | replaces retained AP IE |
| wapi_sm_set_header | uint8_t * (uint8_t *header, uint32_t sequence, uint8_t subtype) | writes 12-byte header; returns header+12 |
| wapi_sm_asue_challenge | void (uint8_t *out, uint32_t length) | OS get_random(out,length), logs negative result; no propagated status |
| wapi_sm_check_header | int (void *sm, const uint8_t *header, const void *unused, uint16_t length) | validates header; 0/-1 |
| wapi_txcb | void (void) | uses global context; multicast key install/auth completion |
| key_derivation_hmac_sha256 | void (const uint8_t *key, int key_len, const uint8_t *text, int text_len, uint8_t *output, int length) | iterative HMAC expansion below |
| wapi_sm_deinit | int (void) | destroy global context, unregister callbacks |
| esp_wifi_internal_wapi_deinit | int (void) | forwards wapi_sm_deinit result |
| wapi_sm_set_own_addr | void (void *sm, const uint8_t *mac) | copies six bytes to sm+0xcc |
| wapi_sm_init | int (void) | create global context and register callbacks |
| esp_wifi_internal_wapi_init | int (void) | forwards wapi_sm_init result |
| wapi_process_packet_type | int (void *sm, const uint8_t *header, uint16_t length) | header validation, fragment accumulation, subtype processing |

SM4 is the standard 32-round 128-bit block cipher. Read/write block words big-endian. Round-key expansion starts with the standard FK XOR, byte Sbox substitution and key linear transform with rotations 13,23; round linear transform uses rotations 2,10,18,24. Output words are reversed. Public encrypt/decrypt both return 1 immediately for zero length and do not touch buffers. Nonzero input produces length output bytes and returns 0. Start feedback with IV; for every 16-byte segment transform feedback, XOR with the input segment, and use the transformed feedback for the next segment. Encrypt transforms with normal SM4 encryption round-key order; **decrypt transforms with the reversed round-key order**. Thus the exported decrypt is not the mathematical inverse of exported encrypt. Preserve the observed difference. Partial segments use only the required prefix. No padding is emitted; IV/key buffers are unchanged; exact input/output aliasing is supported.

MIC zero length also returns 1 without output. Otherwise initialize accumulator as SM4_encrypt(key, IV). For each full block, replace accumulator with SM4_encrypt(key, accumulator XOR block). A trailing partial block is zero-padded to 16 bytes before this step. Write final 16-byte accumulator; return 0. Do not add an extra block on exact multiples.

HMAC expansion uses wpa_crypto_funcs.hmac_sha256_vector (table byte offset 8). First digest = HMAC-SHA256(key, text); each later digest = HMAC-SHA256(key, previous 32-byte digest). Concatenate and truncate to requested length. No counter, salt, or separator is inserted. For exact multiples, the final 32-byte digest may use temporary storage but observable output is identical. Callback arguments are key,key_len,1,&data_pointer,&data_length,digest_output; callback return is ignored. Zero output length generates no output. Ordinary use requires a nonnegative length; negative values are not uniformly rejected (the original uses an unsigned loop bound after adding31), so no bounded safe behavior is promised. A NULL callback skips operations; a final partial block then copies indeterminate stack bytes in the original, so it has no stable output contract.

## Context offsets

| Offset | Width | Meaning |
|---|---:|---|
| 0x000 | 4 | owned callback table pointer; 16 bytes |
| 0x004 | 4 | negotiation state |
| 0x008 | 4 | parameter ID 0 |
| 0x00c | 96 | unicast key slot 0 |
| 0x06c | 96 | unicast key slot 1 |
| 0x0cc | 6 | own MAC |
| 0x0d2 | 6 | BSSID |
| 0x0d8 | 4 | active unicast key ID |
| 0x0dc | 4 | multicast key ID |
| 0x0e0 | 32 | station/ASUE challenge |
| 0x100 | 32 | AP/AE challenge |
| 0x120 | 4 | owned association IE pointer |
| 0x124 | 4 | association IE length |
| 0x128 | 4 | owned AP IE pointer |
| 0x12c | 4 | AP IE length |
| 0x130 | 16 | base key BK |
| 0x140 | 16 | base-key identifier BKID |
| 0x150 | 32 | derived multicast encryption/integrity keys |
| 0x170 | 2 | received packet sequence, host endian |
| 0x172 | 2 | transmitted packet sequence, host endian |
| 0x174 | 4 | parameter ID 1, pairwise cipher |
| 0x178 | 4 | parameter ID 2, group cipher |
| 0x17c | 4 | parameter ID 3, key-management bits |
| 0x180 | 4 | pending pairwise install key ID |
| 0x184 | 1 | driver key slot |
| 0x185 | 1 | multicast rekey flag |
| 0x186 | 16 | saved multicast key announcement identifier |
| 0x198 | 4 | owned 16,384-byte fragment buffer |
| 0x19c | 4 | accumulated fragment payload length |
| 0x1a0 | 12 | last fragment WAI header |

Each unicast 96-byte slot has encryption key at +0, integrity key +16, handshake HMAC key +32, multicast wrapping key +48; remaining +64..95 are also derived. No names for those remaining bytes are assumed. Context callback table: +0 remains zero after initialization; +4 set_key(sm,algorithm,peer,key_id,set_tx,sequence,sequence_len,key,key_len); +8 get_bssid(sm,out6); +12 ether_send(sm,dst,ethertype,payload,uint16_length).
