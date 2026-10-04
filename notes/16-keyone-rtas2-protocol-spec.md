# KEYone — RTAS2 / authboot Protocol Specification

Date: 2026-10-02
Sources: `pcauthtool.exe` (Windows PC client), `bbauthtool` (LK side), `aveflash.lua`/`authboot.exe`.

## Message types (from pcauthtool.exe struct names)

```
msg_header_t                 common header: cookie, msg_size, version
msg_pc_handshake_dev_t       PC -> DEV handshake
msg_dev_handshake_pc_t       DEV -> PC handshake (bootchain ver, HLOS ver)
msg_dev_password_pc_t        DEV -> PC password prompt
msg_pc_password_dev_t        PC -> DEV password (password_hash_with_entropy, password_buf, password_size)
msg_dev_rtas_chal_pc_t       DEV -> PC RTAS challenge (rtas_chal, rtas_chal_len)
msg_pc_rtas_chal_dev_t       PC -> DEV RTAS response (rtas_resp, rtas_resp_len)
```
Additional structs seen: `header_t`, `feedback_header_t`, `response_t`, `configure_t`,
`authenticate_header_t`, `challenge_response_length`, `rtas_credentials{version,rtas_server,rtas_user,rtas_pass}`.

## LK-side event state machine (bbauthtool)

```
EVENT.HANDSHAKE
EVENT.PASSWORD
EVENT.RTAS_INIT
EVENT.RTAS_HAS_PERM
EVENT.RTAS_SIGN
EVENT.DISCONNECTED
```
Sequence:
```
handshake -> (password?) -> RTAS_INIT -> RTAS_HAS_PERM -> RTAS_SIGN
```

## Functions

PC side: `process_handshake`, `process_password`, `process_rtas_chal`,
`calculate_password_hash[_with_entropy]`, `get_user_password`,
`BBAuthDecryptRtasBlob2`, `BBAuthVerifyCred`, `get_rtas_cred_from_file`.

LK side: `bbauthtool_sock_client_register/send`, `auth_rtas_init`,
`auth_rtas_has_permission`, `auth_rtas_sign_record`, `auth_password`.

## Validation (LK) — the un-hardened parser

```
bbauthtool: Invalid sock message cookie: 0x%08X
bbauthtool: Invalid message cookie: 0x%08X
bbauthtool: Invalid event cookie: 0x%08X
bbauthtool: Invalid password response size: %u
bbauthtool: Unexpected password response: %u
bbauthtool: Invalid rtas_has_permission response size: %u
bbauthtool: Unexpected rtas_has_permission response: %u
bbauthtool: Invalid rtas_init response size / status
bbauthtool: Password (size) mismatch
```
Each message carries: **cookie (magic)**, **size**, **code/version** — the classic
size-trust pattern that produced KEY2's CVE-2021-1931. These checks are the *only* barrier.

## Password flow

- `is-password-set` -> `ro.boot...` / `getvar is-password-set`
- **This device: password NOT set** (`is-password-set: no`, `oem info: is-password-set no`).
- LK: `bbauthtool: No password set` -> password step skipped; flow proceeds to RTAS_INIT.
- `pcauthtool -b` bypasses the RTAS credential check at launch.
- The autoloader: `No need to load pcauthtool, device has no password`.

**Consequence:** on a no-password device the RTAS2 flow is reachable without PC-side
credentials — ideal for capture/replay/fuzz. The RTAS server (`rtasinsidebb.rim.net`) is dead
(services shut down), so `RTAS_HAS_PERM`/`RTAS_SIGN` likely fail closed — but the *message
parsers* run first and are the target.

## Transport

- `authboot.exe` (BlackBerry fastboot fork) drives it over USB; `bbauthtool` runs in the
  bootloader and also exposes a **socket** (`bbauthtool_sock_client_*`) to `bbauthtoold`.
- `disconnect`/`device_send`/`device_receive` helpers in pcauthtool (`data_size`, `msg_size`).

## Attack plan

1. **Enumerate the authboot USB interface** (bootloader mode) — VID/PID differs from plain
   fastboot; capture descriptors.
2. **Capture a real exchange**: run `authboot.exe`/`flashall.bat -c debugtokens -l all` while
   sniffing USB (USBPcap on Windows, or `usbmon` on Linux). Record every `msg_*` frame.
3. **Replay & mutate**: rebuild frames with `tools/authboot_client.py` (libusb), mutate
   `msg_size`, cookie, and per-field sizes to probe the LK parser (`authboot_check_permission`
   -> `bbauthtool` handlers). Target: a size-trust bug that reaches `dbg_token_insert`
   (write a token) or `set_device_unlock`.
4. If a token can be written -> `/nvuser/hlos_unsigned.tkn` -> boot-load skips image
   verification (notes/15) -> custom OS / root.

## Reconstructed frame layout (working hypothesis)

```
struct msg_header_t {        // every frame
    uint32_t cookie;         // magic, validated ("Invalid message cookie: 0x%08X")
    uint32_t msg_size;       // total/remaining size, validated
    uint32_t version;        // protocol/pcauthtool version
    uint32_t code;           // message code (EVENT.*)
};
```
Then per-message payload (handshake versions; password hash+entropy+size; rtas chal/resp).

## Files
- `firmware/.../host/windows-x86/bin/pcauthtool.exe`, `authboot.exe`
- `emmc_appsboot.mbn` (bbauthtool strings/symbols)
- `aveflash.lua` (drives `authboot debugtokens`)
- notes/11, notes/15
