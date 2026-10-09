# Packet handling and key negotiation

This describes observed behavior, including permissive checks and failure residue. It does not claim standards conformance. All offsets below refer to WAI payload immediately after the 12-byte header. Key derivation and handshake MIC use HMAC-SHA256; the packet MIC is the first20 digest bytes (different from WPI/SM4 MIC).

## Receive boundary

Driver receive callback ABI is int receive(void *unused,const uint8_t *wai,uint32_t available_length). It uses global sm. Only key-management exact0x1000 or0x2000 is supported. Require available_length>27 and available_length>=encoded BE16 WAI length. It reads encoded length before validating available bytes. A decreasing sequence logs a warning but is **not rejected**: received sequence is always replaced with packet BE16 sequence BEFORE calling process_packet_type. Consequently the latter's monotonic check cannot reject a replay through this callback. Pass available_length (truncated to16 bits by callee) to process_packet_type, so surplus trailing data causes header length mismatch. Return status from processing. On nonzero status and current state>=3, invoke deauthenticate(1); no local state reset. Original NULL-global path logs but later dereferences global during error cleanup, so NULL-global receive has undefined/crashing behavior; do not claim safe return-1.

## Fragmentation and dispatch

Process first calls header checker; checker -1=>process -1 immediately, leaving old fragment state. Payload length = low16(encoded_length-12).

If prior saved fragment flag (sm+0x1ab) is nonzero and either incoming sequence differs from current sm received sequence or incoming fragment number==0, free old fragment buffer, clear pointer/count and saved12-byte header. This uses sm received sequence, not saved-header sequence; receive boundary already overwrites it.

Incoming fragmentation flag nonzero means more fragments. If no buffer exists, malloc16384 and copy first payload, without checking allocation result or first fragment number or first-fragment payload bounds; store count and saved header, return0. If buffer already exists, validate next-fragment rules below, append payload, update count/header, return0. For flag0 with prior saved flag nonzero, validate, append, use whole accumulated payload, clear saved header/count; leave buffer live until final dispatch cleanup. Other flag0 packets use in-place payload. Unknown nonzero flag values are treated as true.

Validation requires incoming fragment number==(saved number+1), with integer addition (saved255 cannot accept incoming0); exact equality of the raw two sequence bytes; same subtype; signed sum of new payload length plus accumulated count <=16384; non-NULL buffer. On any failure log, clear received sequence to0, free buffer, clear pointer/count/saved header, return-1. Successful validation has no writes.

Dispatch supported subtype8=>unicast request,10=>unicast confirmation,11=>multicast announcement. Subtypes1,5,9,12 are accepted/no-op after header checks (1/5 usually filtered by checker); subtype2 explicitly returns-1 (normally checker filters it); all other subtypes log and return0. No certificate authentication body exists for subtypes3..7. After non-fragment-return dispatch, free non-NULL fragment buffer and clear pointer. State/error changes from dispatch persist.

## Shared helper checks

Key-ID checker accepts only0/1, else-1. ADDID is12 bytes: six BSSID bytes then six own MAC bytes, compared in that order via get_bssid callback. Mismatch=>-1. Handshake MIC verification rejects key_id>=2 with-1; NULL HMAC callback=>-2; otherwise HMAC(key=sm+0x2c+96*id,keylen16,data,payload_length), compare first20 against supplied MIC; mismatch=>-1, match0. Generation clears a temporary32-byte digest, invokes callback if present, then copies20 digest bytes only if callback exists; NULL callback leaves caller's MIC destination unchanged.

## Subtype8: unicast request (1/3)

Payload exactly62 bytes:

| Offset | Size | Field |
|---|---:|---|
|0|1|flags|
|1|16|BKID|
|17|1|USKID|
|18|12|ADDID|
|30|32|AE challenge|

Allowed states0,2,3,5,6 (state<7 and corresponding bit set in0x6d). Invalid state/length=>-1. If AKM exactly0x1000 or0x2000, derive BKID16=HMAC-expansion(BK16,BSSID||ownMAC,12). Compare received BKID; mismatch=>-1. Invalid USKID=>-2; ADDID mismatch=>-3. If flag0x10 is set while state is neither0 nor6, return-4. Otherwise:

1. Generate32 ASUE challenge bytes into sm+0xe0 using random callback (negative random status only logs).
2. Copy AE challenge to sm+0x100. Store active USKID at0xd8 and pending ID=(USKID&1) at0x180.
3. Derivation input is ADDID12 || AE challenge32 || ASUE challenge32 || ASCII `pairwise key expansion for unicast and additional keys and nonce`64 bytes, no NUL; total140. Expand BK16 into96 bytes in selected unicast slot.
4. Set state6 before emitting reply; increment transmit sequence modulo65536.
5. Emit150-byte subtype9 reply: header12 (length150); request first30 payload bytes; ASUE challenge32; AE challenge32; retained association IE; MIC20. The fixed positions assume association IE24: IE starts at reply offset106, MIC at130. Copy uses stored IE length without bounds checks, while MIC input is always118 bytes beginning at reply offset12. Reply buffer is zeroed150 bytes before filling.
6. Generate MIC from selected slot handshake key; get BSSID; ether_send(sm,bssid,0x88b4,reply,150). Zero send status=>0; nonzero=>-1. State6, derived keys, and sequence remain changed on send failure.

## Subtype10: unicast confirmation (3/3)

Require state6 and payload length==62+stored_AP_IE_length+20. Layout first30 bytes same as request; bytes30..61 ASUE challenge; bytes62..(62+AP_IE_len-1) AP IE; trailing20 MIC.

In order require matching BKID16, USKID0/1, ADDID, ASUE challenge32 equal retained challenge, AP IE exact bytes, valid MIC over all payload excluding last20 using received USKID. Any failed check=>-1 (including MIC callback unavailable). Incoming USKID need not equal active USKID. Successful MIC verification does not alter stored challenge/IE.

Obtain BSSID. Copy **active slot** first32 key bytes to temporary, reverse bytes separately in each16-byte half; context key material itself remains unreversed. Call set_key(sm,pairwise==0x400?4:0,bssid,pendingID,1,initialPN,16,tempKeys,32). InitialPN=36,5c repeated8. Ignore install result. Set state0 and pendingID0; return0. This path does not call auth-done; group-key txcb later does.

## Subtype11: multicast announcement (1/2)

Require state0, exact84-byte payload. Layout:

|Offset|Size|Field|
|---|---:|---|
|0|1|flags|
|1|1|MSKID|
|2|1|USKID|
|3|12|ADDID (copied into reply; not checked on this path)|
|15|16|packet number (not checked or installed here)|
|31|16|key announcement identifier / wrapping IV|
|47|1|encrypted-key length, must16|
|48|16|encrypted multicast secret|
|64|20|MIC|

If flag0x10 set, immediately store rekey flag1 at0x185 before subsequent checks; flag0x20 (STAKey) is unsupported=>-1. Validate MSKID and USKID each0/1; verify MIC of first64 payload bytes with received USKID. Copy announcement identifier to sm+0x186 **before** requiring encrypted-key length16. Failures do not roll back prior changes.

Set multicast ID from received MSKID. Unwrap secret using exported WPI **encrypt**, in-place on16 encrypted bytes with IV=announcement identifier and key=received unicast slot+48. Derive multicast32 using recovered16-byte secret as HMAC key, label `multicast or station key expansion for station unicast and multicast and broadcast` exactly82 ASCII bytes (no NUL), store at0x150.

Increment TX sequence modulo65536. Emit63-byte subtype12 reply, header length63; payload first15 bytes from request, then announcement identifier16, then20-byte MIC. Generate MIC over reply payload31 using **active slot** handshake key (may differ from received USKID). Obtain BSSID. If rekey flag set: clear flag, increment low final identifier byte in reply (reply offset42) modulo256 and sm+0x195 modulo256 **after MIC generation**, without carry or MIC recomputation. Send reply with EtherType0x88b4, length63. Send zero=>0 else-1. No key install or auth-done here; tx completion callback performs them. State remains0. On send failure derived keys, IDs, sequence and rekey changes remain.

## States and unsupported semantics

State1 is initialized, state2 means base key derived, state3 association notification received, state6 unicast reply prepared/waiting confirmation, state0 idle/unicast installed. State5 is accepted by request but no observed body assigns it. State4 is rejected by request; no observed body assigns it. External writes through opaque context are outside ordinary initialization flow. No retry timer, certificate verification, deauthentication reset, credential lifetime policy or sequence anti-replay robustness is inferred beyond these bodies.
