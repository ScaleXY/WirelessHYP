# HYP2003 ESP32-S3 signing service

ESP-IDF 6.0.2 firmware for an ESP32-S3 using its native USB OTG controller as a **USB host** for HyperSecu HYP2003 (`2ccf:080a`). UART0 provides an ordered JSON-lines P-256 signing service compatible with the Pi daemon. Wi-Fi STA/SoftAP and an authenticated HTTP(S) management interface run alongside the UART signer. No OpenSC runtime or PC/SC daemon is used.

**Hardware has not been attached or tested.** The ESP32-S3 build and native tests pass; this is an implementation for hardware bring-up, not a claim of verified HYP2003 compatibility. Non-FIPS AES and 3DES secure messaging match OpenSC's actual source routines in native comparisons. FIPS mode is refused before PIN authentication because the reference does not specify/check its response MAC.

## Wiring and power

- Use the DevKitC **UART** USB-serial bridge connector for power, flashing and the protocol (UART0 GPIO43 TX / GPIO44 RX, 115200 baud by default).
- Connect the token through a suitable OTG host adapter to the **native USB** connector (GPIO19 D− / GPIO20 D+). This port is occupied by USB host mode, so it cannot also provide the serial protocol or USB device console.
- The token needs regulated **5 V on VBUS**. The S3 DevKitC native connector generally does not source VBUS merely because firmware selects host mode. Check the exact board revision's schematic and its 5 V / USB-OTG power jumper configuration. The usual fix is a correctly wired 5 V VBUS source or a powered USB hub. Supply enough current for board and token, use common ground, and avoid backfeeding two 5 V sources. USB controller “port power” does not switch an external VBUS supply on an unmodified board.
- Logs default to a separate UART1 **TX GPIO17**, 115200 baud. Connect another 3.3 V serial adapter if logs are wanted. `HYP_LOG_TX_PIN` changes the pin; `HYP_SILENT_LOGS` silences application logs. Do not select GPIO19/20/43/44 or a board-reserved pin for log TX.

IDF's primary and secondary consoles are disabled and bootloader logs are disabled. The immutable ROM reset/download banner may still appear on UART0. It is ordinary text, never protocol JSON. Consumers must ignore non-JSON lines. Application output on UART0 consists only of complete JSON lines; no PIN, private key, or SM session key is logged. Do not use `idf.py monitor` and the test script on the same serial port simultaneously.

## Build and flash

```sh
source ~/.espressif/tools/activate_idf_v6.0.2.sh
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/cu.usbserial-YOUR-BRIDGE flash
```

Run `idf.py menuconfig` → **HYP2003 signer** to set baud, logs and CCID timeout. `sdkconfig.defaults` uses a 4 MB flash chip and `partitions.csv`: NVS at 0x9000 (64 KiB), PHY at 0x19000 (4 KiB), and one factory application at 0x20000 (3968 KiB). There are no OTA slots; use UART flashing for updates. Adjust flash capacity for your board. The managed dependencies are `espressif/usb` 1.5.0 and `espressif/mdns` (locked in `dependencies.lock`); ESP-IDF v6 moved the host library out of tree. All project C components compile with `-Wall -Wextra -Werror`.

The PIN and fatal latch survive ordinary builds, flashes, resets and USB replugs. Firmware **never erases NVS** to repair an initialization error. A corrupt/unreadable NVS store fails closed. An explicit whole-flash/NVS erase outside this firmware destroys the latch and is outside its safety guarantee.


## Wi-Fi and browser setup

Copy the empty secrets template before a local build:

```sh
cp sdkconfig.secrets.example sdkconfig.secrets
# Edit sdkconfig.secrets privately, then rebuild from defaults:
rm -f sdkconfig
idf.py build
```

`sdkconfig.secrets` is gitignored. CMake adds it after `sdkconfig.defaults` unless `-DHYP_NO_SECRETS=1` is supplied. Existing sdkconfig values take precedence; remove sdkconfig when changing defaults. Never publish local build outputs: a locally built binary contains the configured PIN and initial admin password in flash, even after NVS credentials change. Use flash encryption and secure boot for production, together with NVS encryption as appropriate. `CONFIG_HYP_PUK` is reserved for a future unblock feature. No firmware code reads it, so its value is not included in the app binary.

PIN and admin defaults seed only absent NVS credentials once. Explicit UART provisioning wins across reflashes. PIN seeding never clears `pin_rejected`; only an explicit `set_pin` retains that authority. NVS errors fail closed and never trigger an erase. Passwords and PINs use NVS blobs to avoid the debug logging performed by `nvs_set_str`.

Set an admin password of 8–64 characters through the private fragment or UART:

```json
{"id":5,"op":"set_admin_password","password":"<your password>"}
{"id":5,"ok":true}
```

Use 8–63 characters if SoftAP setup is needed: WPA2 passphrases cannot represent an arbitrary 64-character password. A 64-character admin password remains valid for browser login on STA, but disables SoftAP startup. Setting a password over UART invalidates existing sessions. The Wi-Fi task starts web services once a password becomes available.

With no saved profiles, join `WirelessHYP-XXXX` (last two STA MAC bytes) using the admin password, then open `https://192.168.4.1/` or `https://wirelesshyp.local/`. Sign in and add up to eight Wi-Fi profiles. Wi-Fi passwords never appear in API responses. Visible known networks are selected by priority, then RSSI; unobserved hidden profiles are attempted after visible profiles. Disconnects rotate candidates with exponential backoff (up to 32 seconds). A connection attempt times out after 12 seconds. If STA has not connected after 30 seconds, SoftAP also starts; STA keeps retrying. SoftAP stops 60 seconds after STA obtains an address. A changed admin password becomes the AP passphrase on its next start. With no admin password, SoftAP and both web servers are disabled.

The device generates an EC P-256 self-signed certificate and private key once, stores them in NVS, and reuses them. Browsers display an untrusted certificate warning. Verify the certificate SHA-256 fingerprint through `GET /api/status` over a trusted setup connection and compare it with the browser certificate viewer before trusting future connections. The certificate has CN and DNS SAN `wirelesshyp.local`; dynamic IP addresses are omitted. Without a trusted RTC, validity is anchored to the release epoch, 2026-11-01 through 2036-11-01 (ten years), rather than the unknown first-boot date. An IP URL can also produce a hostname warning.

Menuconfig offers HTTP `redirect` (default; 301 to `https://wirelesshyp.local/`), `serve` (the same authenticated app on port 80), or `off`. Plain HTTP exposes traffic to observers; use HTTPS on untrusted networks. HTTPS always uses port 443 when web services are enabled.

The JSON management API is under `/api/`. Every non-GET request, including login, requires `X-HYP: 1`. Only `GET /api/session` and `POST /api/login` are public. Login issues an HttpOnly, SameSite=Strict session cookie (Secure on HTTPS); four sessions are allowed, with 12-hour idle expiry. Five failures lock login for 60 seconds. Body limit is 1024 bytes; malformed, duplicate-key, nested, and oversized JSON requests are rejected. Request bodies are flat objects with strings, integer numbers and booleans. The interface manages status, profiles, scans, admin password and reboot; it never signs or provisions a token PIN. Token status comes from a mutex-protected snapshot published by the signer loop. Profile persistence and authentication state are also protected by a mutex. The UI file in `main/web/index.html` is embedded and served as supplied.

## CI

`.github/workflows/build.yml` runs on pushes and pull requests with read-only repository permissions. It builds ESP32-S3 firmware with ESP-IDF v6.0.2 without a secrets fragment and uploads only flash binaries and flasher arguments. The Linux host job installs OpenSSL development headers, checks out OpenSC `3856d69`, and runs the sanitizer-enabled native suite, including web logic and PIN seed/marker safety. Never add secret values to GitHub workflow inputs, logs or artifacts.

## Provision and test on hardware

Install the two host-tool dependencies in your preferred Python environment:

```sh
python3 -m pip install pyserial cryptography
python3 tools/hyp_sign.py /dev/cu.usbserial-YOUR-BRIDGE --set-pin --count 10
```

The tool obtains the PIN with a hidden terminal prompt, sends `set_pin`, obtains `ready` (or queries `pubkey` if it missed the event), signs random 32-byte digests, verifies with P-256 using `Prehashed(SHA256)`, and asserts low-s. `Prehashed` ensures the verifier does **not** hash the digest again. Subsequent runs omit `--set-pin`. DTR/RTS are held deasserted; some USB bridges may nevertheless reset a board on port open.

Provisioning stores the PIN as an NVS blob, **not encrypted by this project**. Use a protected UART link and provision board flash/NVS encryption separately if physical flash confidentiality is required. Do not place real PINs in shell command arguments, source files, logs or checked-in configuration. The firmware never changes a token PIN, creates keys or modifies the token's PKCS#15 files.

The token must already contain the OpenSC epass2003-profile P-256 key with CKA_ID `01` (expected label `gbx-test-p256`) and readable PKCS#15 directory files, as described in the task. Lookup uses the ID, not the label. MF/AppDF is `3F00/5015`, ODF is `5031`. ODF paths identify PrKDF/PuKDF/AODF; no key-file or PIN-reference brute force is performed.

## JSON lines

Every request and response ends in LF. CRLF input is accepted. Requests run serially, in order. IDs are optional signed 64-bit JSON integers and are echoed exactly as integers; fractional/exponential IDs, duplicate/unknown fields and oversized/binary lines are rejected. The maximum accepted line is 511 bytes. Strings use ASCII JSON escapes; PINs are printable ASCII, with 4–16 bytes required by the card driver.

```json
{"ready":true,"qx":"0x<64 hex>","qy":"0x<64 hex>"}
{"id":1,"digest":"0x<64 hex>"}
{"id":1,"r":"0x<64 hex>","s":"0x<64 hex>","ms":11.200}
{"id":2,"op":"pubkey"}
{"id":2,"qx":"0x<64 hex>","qy":"0x<64 hex>"}
{"id":3,"op":"status"}
{"id":3,"token":"ready","pin_set":true,"pin_rejected":false}
{"id":4,"op":"set_pin","pin":"<PIN>"}
{"id":4,"ok":true}
```

`op` absent or `"sign"` signs; the digest must match `^0x[0-9a-fA-F]{64}$`. There is no extra hashing or EC input padding. Signatures are raw 64-byte big-endian r‖s; the firmware validates the scalars and replaces high s with n−s. Responses split the result into fixed-width hexadecimal `r` and `s`. `ms` measures operation time including any reopen/retry, excluding UART transmission. The example timing is illustrative, not measured on the ESP32.

`status.token` is `absent`, `present` (USB token found but signing session unavailable), or `ready`. Normal failures return `{"id":n,"error":"..."}`; examples are `bad digest`, `no HYP2003 token present`, `token error: ...`, and `key id 01 not found on the token`.

PIN refusal returns `{"id":n,"fatal":"pin_rejected","error":"..."}`. An asynchronous fatal announcement can omit `id`. All sign/pubkey requests while latched receive that fatal result. `status` and `set_pin` remain available. `set_pin` acknowledges its durable update **before** trying to open the token, so a ready/fatal event may follow its `ok` response. Treat every explicit `set_pin` as permission to try the newly supplied PIN again; do not automatically replay that operation.

## PIN safety and recovery

The persistent `pin_rejected` marker is a versioned blob containing an error code and time in microseconds since the boot in which it was written. There is no wall-clock source. The marker itself never contains the PIN. PIN storage uses `nvs_set_blob`, because IDF's `nvs_set_str` debug log prints its value.

Before calling the authentication function, the service durably commits a **write-ahead guard** as the marker. It then makes at most one external-authentication attempt. It clears the guard only after authenticated success. A `63Cx`, `6300`, `6983`, `6984`, `6700`, `6A80`, or local invalid PIN length is latched. Other authentication failures, MAC errors, USB disconnects, and interrupted/unconfirmed authentication are also conservatively latched. This intentionally prevents a second potentially wrong attempt when the result was lost. A power cut after success but before clearing the guard can therefore require `set_pin` even for a correct PIN.

The marker is checked **before token preparation or authentication** on every open. Once latched, no retry, periodic recovery, reboot or replug calls authentication. Only `set_pin` clears it. PIN replacement is committed before marker clearance. If committing the guard fails, no authentication is sent. If clearing it fails, the service remains latched. Empty PIN provisioning is rejected without changing state; an out-of-range nonempty PIN is stored but latched by the subsequent open without sending it to the card.

There is **no post-VERIFY retry-count query**. OpenSC's external-key challenge-response serves as PIN verification; the problematic empty `82 01 8x` retry query is never generated. There is also no automatic authentication APDU replay or SM refresh inside the card driver.

Sessions and SM keys remain in RAM between requests. Open performs a card power cycle, app selection, SM mutual auth, readable PKCS#15 reference discovery, one guarded PIN authentication, and the public-point read. AODF discovery deliberately precedes PIN authentication to resolve the key's authId to the actual PIN reference safely. Files under FID prefixes `29`–`34` use OpenSC's low-byte ×0x20 mapping. The private key file is never read.

A nonfatal token-operation failure gets one full reopen and one retry. Fatal errors are never retried. USB disconnect generation changes fail the in-flight operation; the next attach is opened eagerly (or by the next request). A fresh `ready` event is emitted on every successful reopen, and UART1 warns if its public point differs from the first one seen since boot. Errors leave the service running. `main/transport.h` is the small line-in/line-out boundary for a future TCP implementation.

## Driver/reference implementation

`components/ccid_host` owns a single asynchronous USB host client, pumps its events on the service task, and runs the USB library daemon separately. It claims the matching token's CCID or vendor-specific interface, finds bulk IN/OUT plus optional interrupt IN, parses `dwFeatures`/maximum CCID message length, and uses slot zero. Interrupt IN is discovered but bulk status and USB attach/remove events suffice for this integrated token; no interrupt transfer is needed. Bulk input is reassembled using the 10-byte CCID header and explicit payload length, tolerating USB packet fragmentation and CCID time extensions within a configured hard transaction deadline. Transfers are halted/flushed and callbacks drained on timeout; live transfer objects are never freed under a pending callback.

The implementation covers PowerOn/Off, GetSlotStatus and XfrBlock with sequence checking, short/extended APDU exchange, and extended CCID command/response chaining. Descriptor-required T=1 TPDU mode has I/R block sequencing, IFSC, LRC/CRC, response chaining and S-block WTX/IFS handling. It requires direct-convention T=1 and reader automatic ATR configuration/parameter negotiation; character-level, T=0 TPDU, inverse convention and manual PPS are explicitly refused rather than sending APDUs at the wrong exchange level. The CCID chaining rules and CRC convention were checked against [libccid](https://github.com/LudovicRousseau/CCID/tree/master/src).

`components/epass2003` is derived from [OpenSC `card-epass2003.c` at 3856d69](https://github.com/OpenSC/OpenSC/blob/3856d69/src/libopensc/card-epass2003.c). The needed logic was adapted from:

- `get_data`, `gen_init_key`, `verify_init_key`, `mutual_auth` / `epass2003_refresh`: mode discovery, session derivation, card cryptogram verification and host authentication.
- `construct_data_tlv`, `construct_le_tlv`, `construct_mac_tlv`, `encode_apdu`, `epass2003_sm_wrap_apdu`: encrypted DO87, DO97, counter and DO8E MAC.
- `epass2003_check_response_mac_and_sw`, `decrypt_response`, `epass2003_sm_unwrap_apdu`: status binding, response MAC and strict ISO 7816 padding validation, including the reference's faulty one-byte-length workaround.
- `hash_data`, `external_key_auth`, the VERIFY branch of `epass2003_pin_cmd`: SHA-1(PIN)‖BE32(PIN length) as the 24-byte 3DES challenge-response key. The retry query branch is deliberately omitted.
- `epass2003_hook_path`, `epass2003_select_fid_`, `epass2003_select_path`, `epass2003_process_fci`: profile paths, mapped FIDs and transparent EF reads.
- `epass2003_set_security_env`, the EC/HASH_NONE branch of `epass2003_decipher`: MSE `00 22 41 B6`, data `80 01 92 81 02 <key FID>`, then PSO `00 2A 9E 9A` with the exact digest.

The [PKCS#11 framework](https://github.com/OpenSC/OpenSC/blob/3856d69/src/pkcs11/framework-pkcs15.c) maps CKM_ECDSA to HASH_NONE. [PKCS#15 signing](https://github.com/OpenSC/OpenSC/blob/3856d69/src/libopensc/pkcs15-sec.c) truncates overlong raw EC inputs to field length; a 32-byte P-256 digest passes unchanged. The minimal DER readers follow `asn1.c`, `pkcs15-prkey.c`, `pkcs15-pubkey.c`, `pkcs15-pin.c` and the epass2003/pkcs15 profiles at that same commit. They use structural parsing, explicit lengths and ID equality, not arbitrary byte-pattern searches.

IDF PSA supplies AES and SHA-1. No DES API/header is exposed by IDF v6's mbedTLS; `des.c` supplies a self-contained FIPS-46-3 DES primitive for two-/three-key 3DES and retail MAC. Host nonces use IDF RNG with the ADC entropy source enabled only during sampling; this project does not otherwise use the ADC. Low-s uses a bounded 256-bit subtraction helper.

## Native verification

```sh
tools/run_host_tests.sh
```

The script uses system `cc`, AddressSanitizer/UBSan and an **already installed** OpenSSL development library as the native crypto/reference backend. It adds no packages. On this Mac it detects `/opt/homebrew/opt/openssl@3`; Linux uses `pkg-config openssl` (install `libssl-dev`), or set `OPENSSL_PREFIX`. Firmware does not link OpenSSL. Python source syntax is checked without importing serial/cryptography or requiring hardware.

Tests always run frozen synthetic vectors generated against OpenSC 3856d69. To rerun the direct original-source comparison elsewhere, clone OpenSC outside this project, checkout `3856d69`, and set `OPENSC_REFERENCE` to its root. Without `OPENSC_REFERENCE`, the script looks for a checkout at `tests/.opensc` (gitignored). The adapter extracts selected original routines into ignored `tests/.build/`; it does not vendor OpenSC into the firmware. OpenSC-derived test adapters/fixtures carry the same LGPL terms as the component.

Coverage includes DES/AES/SHA known answers, CMAC (RFC 4493), AES/3DES session derivation and card cryptograms, ten wrapped APDUs and two independently encrypted/MACed responses, MAC/SW tampering, CCID framing/errors/extensions/chaining, T=1 I/R/WTX/CRC, bounded DER/PKCS#15 key and PIN-reference parsing, exact PIN/signing APDUs, digest/JSON validation/formatting, low-s boundaries, and a mock-backed persistent-marker test across open/replug/reboot and storage failures. No physical token PIN is used by any native test.

Run the commands above for current build/test output and image size. Generated result logs are not tracked. `build/hyp_signer.bin` is the flashable app (bootloader and partition table are also needed; use `idf.py flash`).

## Open hardware doubts and limits

1. **Actual descriptor/exchange mode:** HYP2003 `dwFeatures`, maximum CCID length, endpoint layout, power-on voltage selection and automatic protocol negotiation have not been observed. Short/extended APDU mode is expected from its libccid behavior. The T=1 fallback is unit-tested, not device-tested; readers needing manual PPS/parameter setup are refused.
2. **FIPS:** OpenSC's response verifier explicitly accepts FIPS responses without checking their MAC. Its FIPS response MAC construction cannot be confirmed from this source. This firmware fails with `EP_UNSUPPORTED` before any PIN in FIPS mode; no guessed algorithm or unchecked response is used. Non-FIPS AES and 3DES match the reference. Confirm which mode the HYP2003 reports via GET DATA `CA 01 86` during bring-up.
3. **Profile/layout:** `3F00/5015/5031`, readable directories, EC choice encoding, authId and explicit key/PIN references are source-confirmed for the stated profile but have not been read from this particular token. Direct embedded PuKDF keys and nonstandard profiles are unsupported. Public EF data must be DER `04 41 04‖x‖y` with optional zero/FF allocation padding.
4. **Physical response behavior:** raw 64-byte signatures, SW/SM framing, proprietary length workaround, status codes, power cycles and session survival match the stated Pi behavior/reference but require a real token test. This minimal card transport does not implement generic ISO-7816 `61xx` GET RESPONSE or `6Cxx` corrected-Le replay for data-bearing commands; unexpected use fails and triggers the normal one-reopen policy. SELECT-without-FCI permits `61xx`, matching OpenSC. No such replay can accidentally repeat PIN authentication.
5. **USB lifecycle:** packet assembly, timeouts, callback draining, actual unplug-in-flight and same/different-token replug have not been exercised against USB hardware. A pending transfer that cannot be drained is retained and blocks reuse instead of risking use-after-free. Replug/board reset may be needed for a wedged reader; an uncertain PIN attempt remains latched.
6. **Speed/power/PSA:** no measured signing latency, flash/RAM runtime stack watermark, VBUS/current test, or on-target PSA AES/SHA execution test is available. Sessions stay open, so the intended steady-state path is MSE plus PSO, with no directory walk, mutual auth or PIN operation per successful signature. Test first with a known-correct PIN and the Python verifier. Do not intentionally burn retry counters to test the latch.

## Files and licensing

```text
.
├── CMakeLists.txt
├── sdkconfig.defaults
├── dependencies.lock
├── components/
│   ├── ccid_host/
│   │   ├── CMakeLists.txt, idf_component.yml
│   │   ├── include/ccid_host.h
│   │   └── ccid_host.c, ccid_frame.c, t1.c
│   ├── epass2003/
│   │   ├── CMakeLists.txt, LICENSE
│   │   ├── include/epass2003.h
│   │   └── card.c, crypto.c, des.c, sm.c, pkcs15.c, low_s.c
│   └── signer_proto/
│       ├── CMakeLists.txt, include/signer_proto.h
│       └── signer_proto.c
├── main/
│   ├── CMakeLists.txt, Kconfig.projbuild
│   └── app.c, service.c, service.h, transport.h, transport_uart.c
├── tests/
│   ├── test_main.c, test_reference.c
│   ├── fixtures/sm_vectors.h
└── tools/
    └── hyp_sign.py, run_host_tests.sh, extract_opensc_reference.py
```

`components/epass2003/` and OpenSC-derived native-test material are **LGPL-2.1-or-later**, retaining attribution to Weitao Sun and Xiaoshuo Wu and the full LGPL-2.1 text in that component's `LICENSE`. The OpenSC tree is not vendored. Static firmware distribution must account for LGPL source and relinking obligations; retain source and the build's object/archive files for that purpose. The USB component has its own upstream license in its managed package. No commits were made for this implementation.
