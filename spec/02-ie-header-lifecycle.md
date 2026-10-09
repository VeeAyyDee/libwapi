# Information elements, WAI header, lifetime and SDK dependencies

## WAPI information-element parsing

`parsed` is 28 bytes, word offsets: protocol 0, pairwise cipher 4, group cipher 8, key management 12, capabilities 16, unused words 20/24. Always initialize to [4,0x400,0x400,0x1000,0,0,0], even on errors. No NULL output check.

Require length >=4, IE ID 0x44, IE length byte equal to supplied length minus two, little-endian version ==1. Length zero fails without logging; shorter than four fails. After the four-byte prefix, parse in order:

1. If zero bytes remain, succeed with defaults; one byte fails. Otherwise read LE16 AKM count, clear key-management field. Count must be nonzero and fit four bytes per selector. AKM selectors 00:14:72:02 =>0x1000 (PSK), 00:14:72:01 =>0x2000 (certificate), 00:14:72:00 =>0x10; unknown =>0. OR all entries.
2. If zero bytes remain after AKM entries, succeed; one byte fails. Otherwise read LE16 pairwise count and clear pairwise field. Count must be nonzero and fit. Cipher selector 00:14:72:00 =>1; 00:14:72:01 =>0x400; unknown=>0. OR all entries.
3. After pairwise entries zero remaining succeeds with default group cipher. One to three remaining fails. Four or more: parse one group selector with the same mapping.
4. If at least two bytes then remain, consume LE16 capabilities. Ignore any further bytes (log trailing data); even one trailing byte after the group selector is accepted. No BKID list is parsed and unused output words remain zero.

Thus parser deliberately accepts truncated-at-field-boundary IEs, unknown selectors and trailing bytes. It does not validate supported combinations. Failure can leave partially parsed output.

`set_assoc_wapi_ie_default`: require non-NULL sm and *capacity>=24. Output ID44, length22, LE version1, AKM count1, selector PSK=>00:14:72:02 or certificate=>00:14:72:01, pairwise count1, selector00:14:72:01, group selector00:14:72:01, capabilities0000, BKID count0000. Only exact key-management values 0x1000/0x2000 and cipher values0x400 are accepted; invalid values return-1 after preceding output bytes were already written. On success set *capacity=24. If association pointer already exists return0 without replacing its contents or length. Otherwise allocate24, store pointer; failure returns-1, length pointer still24. Copy emitted IE to owned allocation and store context length24. Output itself is caller-owned. Internal assertions spin forever for impossible emitted sizes; ordinary valid configuration cannot reach them.

`set_ap_wapi_ie`: NULL sm=>-1. First free prior AP pointer unconditionally. If input pointer NULL OR length0: clear pointer and length, return0. Otherwise malloc(length), assign pointer immediately; allocation failure returns-1, pointerNULL, **previous length remains**. Success copies bytes and sets length, returns0. Input aliasing prior owned AP storage is unsafe because free precedes copy.

## WAI header

12 bytes: BE16 version at0=1, type byte2=1, subtype byte3, reserved BE16 at4=0, total WAI length BE16 at6, packet sequence BE16 at8, fragment number byte10, fragmentation flag byte11. Header writer initializes length0, fragments0 and writes low16 bits of supplied sequence. Caller fills length later.

Header checker: supplied uint16 length must exceed11; version1; type1. When sm key management exactly0x1000, subtype must be>=8; otherwise subtype>=3. No upper bound. Encoded length must equal supplied length. Incoming sequence must be>=stored received sequence. Return0 if all hold else-1; no writes. Reserved/fragment fields not checked.

## OS, driver and cryptographic boundary

`g_osi_funcs_p` points to pinned `wifi_osi_funcs_t`. Used function-pointer byte offsets on S3:0xb0=_free,0x13c=_get_random,0x168=_malloc_internal,0x174=_zalloc_internal. The latter receives ONE size argument and must return cleared memory. HMAC callback is `wpa_crypto_funcs` structure+8 and uses the SDK signature in public-sdk. No HMAC callback status is propagated.

External driver calls: `wifi_get_macaddr(0,out6)`; `esp_wifi_sta_is_running_internal()` boolean/int; `esp_wifi_auth_done_internal()`; `esp_wifi_deauthenticate_internal(1)`; `ieee80211_register_wapi_cb(table)`; `ieee80211_unregister_wapi_cb()`; `ic_register_tx_cb(wapi_txcb,16,1)`; `ieee80211_output(0,ethernet_frame,uint16_len)`; `ppInstallKey(algorithm,peer,key_id,set_tx,sequence,sequence_len,key,key_len,driver_slot)`.

No driver-private declarations for these calls were found in public headers; these signatures express observed ABI. The callback registration table is seven function pointers in order: receive(unused,data,length), parse_ie(ie,uint8_len,parsed), association_ie(out), ap_ie(ie,length), set_bssid(mac), notify_assoc(), derive_base_key(text,is_hex). All are private functions but are reachable from the driver registration ABI.

Context-local callbacks: get_bssid(sm,out) checks both pointers then copies6; set_key stores sm byte0x184=key_id for all-FF destination else4, then invokes ppInstallKey with the nine arguments above and returns its status. Sequence pointer and key bytes are passed through; the 9th argument is zero-extended stored byte. Ether-send allocates (uint16_length+14), emits dst6, own MAC6, BE16 EtherType, payload; invokes output; frees allocation; returns0 ignoring output status. Allocation failure=>-2. Caller payload remains owned by caller, output receives only a transient borrowed frame.

## Initialization and destruction

`init` zero-allocates28-byte driver table, then428-byte context, then16-byte context-local callbacks. Failures return respectively-1; -2 after freeing driver table; -3 after freeing driver table then context. Publish no global context on failure. Success fills tables, obtains own MAC, clears keys/challenges/IE/fragment/sequence fields, sets state1, publishes global context **before** registering driver callbacks, calls registration, ignores its status and returns0. There is no repeated-init guard: a second success replaces global context without freeing old allocations.

`deinit` with globalNULL=>-1. Otherwise free association IE, AP IE, context-local callback table, fragment buffer, context (in that order, even NULL children). Set globalNULL, then call unregister and return its result. The28-byte registration table is not retained locally or freed here; its ownership is handed to the driver registration/unregistration layer. No key-wiping guarantee before frees.

Private set_bssid checks global and input then copies6 to0xd2. Private notify_assoc sets state3 if global exists. Private parse_ie rejects NULL parsed; truncates supplied length to8 bits; invokes parser, and on success/non-NULL global sets parameters in order AKM(id3),pairwise(id1),group(id2); returns parser status. Private association_ie returns0 for NULL output/failure; otherwise emits with capacity32, calls ic_register_tx_cb, returns24 regardless registration status.

Private derive_base_key does nothing if globalNULL. ASCII branch (is_hex==0) derives16 bytes using text as HMAC key and strlen as key length. Hex branch clears a128-byte temporary, calls hexstr2bin(text,temp,strlen(text)) (actual third argument is full character count, not half), logs conversion failure but still derives using key length floor(strlen/2). Both branches use label `preshared key expansion for authentication and key negotiation` exactly62 ASCII bytes, without NUL, and store BK at0x130; set state2 afterward. The observed hex call is inconsistent with the SDK hexstr2bin contract (which expects output-byte count); preserve as documented discrepancy, do not silently claim ordinary hex decoding equivalence. Input bounds are unchecked.

Auth completion clears state before auth-done, then clears sequence counters after callback. `txcb`: obtain global context, check station running; if false return without further work. If true, obtain BSSID, reverse all16 bytes within EACH multicast16-byte half **in context**, set_key(sm,group==0x400?4:0,FF:FF:FF:FF:FF:FF,multicast_id,1,initial_pn,16,multicast_keys,32), then complete negotiation regardless install result. Initial PN is bytes36,5c repeated eight times (ASCII `6` and backslash). This is a mutating reversal; repeated txcb toggles byte order.
