# notes/44 — Fastboot internals dissection (cmd_download, init, rx vtable)

Date: 2026-10-08
The KEY2-analog hunt: pre-auth fastboot surface of ABL766.

## Command table (discovered)

Registration function around `0x8f62fa68`:
- `"getvar:"` → handler **0x8f62f6bc**
- `"download:"` → handler **0x8f62f3d4**
- further registrations at `0x8f62fa90`+ (`fastboot_publish`, more commands).

## cmd_download @ 0x8f62f3d4

- Hand-rolled hex parser over the argument (jump-table nibble decode; no
  overflow check but maximal wrapping only reduces the value).
- Clamps against `max_download_size` (`0x8f7bc2c4`); failure → `FAIL` +
  `"data too large"`.
- Replies `"DATA%08x"` (`0x8f6d8d88`).
- Calls transport receive via vtable `[0x8f7bc28c + 0x20]` with
  `(download_base, size)`; requires exact byte count back.
- Stores `download_size` (`0x8f7bc280`); error code to `0x8f7bc2cc`.

## fastboot_init @ 0x8f62f8d8

- `download_base (0x8f7bc2d0) = r0` (scratch address arg)
- `max_download_size (0x8f7bc2c4) = r1` (scratch size arg)
- Installs transport vtable at `0x8f7bc28c`:
  `0x8f62409c, 0x8f6246b8, 0x8f62476c, 0x8f624d8c, 0x8f624b14, 0x8f624cc8,
   0x8f624d54, 0x8f62ec6c, 0x8f62eb0c` (+ rx wrappers).
- Published `max-download-size: 0x20000000` comes from the caller's size arg —
  verify what scratch region/size aboot actually passes at boot.

## Transport receive wrapper @ 0x8f62eb0c(buffer,size)

- Asserts non-null/non-zero; queues RX via `0x8f62617c`; waits via
  `0x8f624a2c` with a stack message {ptr,len,cb=0x8f62e7d8}; reads status from
  `0x8f7c3c28`.
- No bounds handling here — the copy/DMA length is whatever was announced;
  the audit must continue into the USB stack (`0x8f62617c`, `0x8f624a2c`,
  endpoint handlers `0x8f6240xx`–`0x8f624dxx`).

## Next audit targets (pre-auth, host-controlled)

1. USB stack completion/packet accounting (`0x8f62617c`, `0x8f624a2c`,
   0x8f6240xx cluster) — the place a KEY2-style overflow would live.
2. `cmd_getvar` @ 0x8f62f6bc + `oem getvarp` formatting (format-string class).
3. Cross-reference known Qualcomm LK / ABL fastboot CVEs (2017–2018) against
   this build's code (fix-list oracle + prior art).
4. Function-level diff across AAK399/AAL093/AAN355/ABL766 to enumerate fixes.
5. Token parser (`hlos_unsigned` path around `0x8f63b95c`) — fuzz input possible
   once `nvuser` write channel exists (modified autoloader flashall experiment).
