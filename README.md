<!-- SPDX-License-Identifier: MPL-2.0 -->
# Fresh libwapi

Readable C implementation of the supplied ESP32-S3 / ESP-IDF 6.0.3 behavioral
specification. The archive keeps the name `libwapi.a`, all 21 strong public
function names and four public data names. It contains semantic implementations,
not an instruction interpreter, embedded original code or success-only stubs.
New implementation and tests are MPL-2.0. The public SDK declaration excerpts
under `spec/public-sdk` retain their Apache-2.0 notices.

## Release status: experimental — WAPI-AP interoperability untested

This release targets ESP32-S3 with ESP-IDF 6.0.3. **Authentication and encrypted
traffic against a real WAPI access point have not been tested.** It is available
for evaluation and interoperability testing; complete behavioral equivalence
and production security are not established.

Evidence supports compatibility on the exercised paths: 324 original-versus-fresh
crypto comparisons, 339 state/protocol comparisons, and an exact target export/data
audit passed. Combined ESP32-S3 hardware testing also passed 432 WAPI crypto checks
across original and replacement builds. These checks do not substitute for a real
WAPI-AP handshake, key updates and protected data exchange. See `VALIDATION.txt`
for scope and known limits. The implementation retains the documented original
quirks and limitations listed below.

An additional independent-reference review passed 1,440 crypto comparisons against
Realtek's WAPI routines, 16 bounded synthetic peer exchanges, and Wireshark parsing
of all 80 exchanged packets. This strengthens the tested compatibility evidence;
it does not establish real-AP interoperability. No implementation changes were
needed. External reference code is not included in this release.

## Build and use

`make all test` builds the native archive and a primitive-only shared library,
runs the SM4 and protocol tests, and audits the archive's complete exported
namespace. `cmake -S . -B build-cmake`, `cmake --build build-cmake` and
`ctest --test-dir build-cmake --output-on-failure` provide the native CMake path.

For firmware, add this directory to `EXTRA_COMPONENT_DIRS` before ESP-IDF
`project(...)`, then include `cmake/replace_wapi.cmake` after `project(...)`.
The hook redirects imported `esp_wifi_wapi` to this component's `libwapi.a`;
it fails for targets other than `esp32s3` or SDK versions other than `6.0.3`.
If the component target was renamed, set `CLEAN_WAPI_COMPONENT_TARGET` to its
actual target name before including the hook. The fresh component must remain
in the application's selected component graph. The hook does not add a dependency
from the imported library back into its component, which could create an IDF
component cycle.

The supplied private driver ABI is declared locally in `src/platform.h`.
The SDK supplies OS allocation/random functions, HMAC-SHA256 and radio callbacks.
Target context offsets and sizes are individually asserted for 32-bit builds.
The 428-byte target context and 16-byte local callback table become native pointer
structures on a 64-bit host. Native OS stubs use target slot indices with native
pointer-sized slots; the crypto table retains two 32-bit prefix fields. Native
context bytes must not be compared directly to target context bytes.

## Implemented behavior

The implementation includes SM4 encryption and reversed-key feedback decryption,
WPI MIC, HMAC expansion through the SDK callback, permissive WAPI IE parsing and
emission, context parameters, lifecycle and callback ownership, header checks,
fragment assembly, unicast request/confirmation and multicast announcement/reply.
The registered driver receive callback is present. Driver-supplied callback tables
and the second zero-allocation expose the same context for external test harnesses;
no additional inspection functions are exported.

Compatibility details deliberately retained include the non-inverse public
"decrypt", receive sequence replacement before header validation, failed AP-IE
allocation retaining its prior length, install/output status handling, byte
reversals at key installation, multicast identifier increment after MIC creation,
repeated-init leaks, and the hex conversion call's character-count discrepancy.
There is no invented certificate authentication, retry policy or state transition.

## Validation and limits

Native tests cover the standard SM4 known block vector in both round-key orders,
zero-length null buffers, lengths 1 through 64 and exact aliasing, MIC zero-padding,
IE boundaries, all three initialization allocation failures, ownership teardown,
a complete unicast/group-key exchange using a deliberately simple deterministic
HMAC callback, MIC rejection, key reversal, send-failure residue and fragmented
packet completion/error cleanup. Additional checks exercise registered callbacks,
receive sequence replacement, surplus-frame rejection/deauthentication, repeated
multicast-key reversal and HMAC truncation for all lengths 0 through 96. The fake digest tests callback framing and state
behavior; it is not a SHA-256 implementation or cryptographic test.

Both native build systems pass. AddressSanitizer and UndefinedBehaviorSanitizer
pass these tests with `ASAN_OPTIONS=detect_leaks=0`; LeakSanitizer is unavailable
under this environment's process tracing. The test allocator independently checks
that its allocations are released on the exercised paths. The supervisor separately
reported 324 primitive comparisons against the original and independent crypto
references; no original binary or runner was available to this implementation side.
Supervisor evidence is summarized separately in `VALIDATION.txt`, including
339 state/protocol comparisons and the target archive audit. These bounded tests
do not establish full protocol or RF equivalence.

Diagnostic log calls are omitted. Their exact text, timing and callback side effects
are not reproduced. Protocol mutations and status handling described in the supplied
specification are retained. HMAC expansion returns without writing output for a
missing callback or a negative requested length; the original has undefined or
unbounded behavior on some such inputs, so those cases are excluded from equivalence.

This is not a memory-safety or security certification. Preconditions and original
unsafe cases remain: readable headers and live contexts at driver boundaries,
allocation success and <=16384 bytes on first fragmented input, valid pointer/length
pairs, fitting retained association IE, and bounded hex credentials. Invalid inputs
can overrun or dereference invalid storage. Repeated init without deinit leaks;
freed secrets are not guaranteed to be wiped. No hardware WAPI association or full
RF/protocol equivalence is established. See `spec/04-coverage-and-limits.md` and
`provenance.json` for the specification boundary.
