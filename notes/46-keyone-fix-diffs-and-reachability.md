# notes/46 — Instruction-level fix diffs + reachability analysis

Date: 2026-10-08
Follow-up to notes/45. Tool: `tools/lk_func_diff.py`.

## What the 2017→2018 fixes actually are

Instruction-level diffs (AAN355 → ABL766), normalized:

1. **Boot-image header parsing (`boot_linux_from_flash`, 0x8f62b914→0x8f62bb94)**
   - 2018 build adds **multiple integer-overflow guards** (`cmp x, C; bhi fail`)
     around the arithmetic on header fields, guarding
     `ERROR: Integer overflow in boot image header %s`,
     `Integer overflow detected in bootimage header fields %u %s`, and
     Device-Tree size checks.
   - Several guards were also *reordered* deeper into the flow.

2. **Boot-image verify (`boot_linux_from_mmc`, 0x8f62ac44→0x8f62aed4)**
   - 2018 build adds **`ERROR: Invalid page size`** early, and
     **`ERROR: Cannot read boot image header after page size updated`** —
     i.e. the header is **re-read and re-validated after the page-size
     field changes it**, closing a TOCTOU-style re-parse gap.

3. **Flash/write path (0x8f62d9ac→0x8f62ddb4)**
   - Adds **`Verified the BOOT_MAGIC in image header`**.
   - Adds explicit **multiplication-overflow checks** on size math
     (`mul` + compare vs 0xffffffff) replacing 64-bit umull logic.

4. **Sparse write path (0x8f62d43c→0x8f62d728)**
   - Gains an additional validation case in the chunk-type jump table
     (one more error handler block; +32 bytes).

## Reachability (critical constraint)

- **`fastboot boot` is not registered**: live test → `FAILED (remote:
  'unknown command')`. BlackBerry LK does not implement `boot:` at all.
- Therefore `boot_linux_from_*` parsers are **only reachable by booting a
  written boot/recovery partition** — i.e. after a flash (**not authboot-gated**
  for boot/recovery: arbitrary bytes can be written pre-auth — notes/49) or via
  another write channel (EDL/root). Note: ABL766 already contains the 2018
  flash-path fixes (notes/45); the vulnerable pre-fix code is only in older
  signed bootchains (downgrade target).
- The **flash-path fixes** are reachable during any `flash:` of those partitions
  (which on ABL766 is open) — the fixes matter when downgrading to an old aboot.
- Pre-auth surfaces that *are* reachable from a hostile host:
  - `getvar:` / `oem` command parsers (read-only probes fuzzable safely)
  - `download:` size handling (buffer = fastboot scratch; published max
    0x20000000)
  - **RTAS / bbauthtool protocol**: triggered by any RTAS-gated command
    (e.g. `flash:`, `oem gptinfo`) — the device then parses *host* messages
    (challenges, responses, cookies, sizes) pre-authorization. Strings show
    many bounds checks (`Too many bytes received: %d>%u`, `Invalid message
    cookie`, `resp_len too large`) — but this is the richest pre-auth parser
    surface, and we already have `tools/authboot_client.py` for the protocol.
  - USB stack core (`0x8f6240xx` cluster, `0x8f62617c`, `0x8f624a2c`).

## Implications

- The clean "feed a malformed boot image via fastboot" idea is dead
  (no `boot:` command).
- The integer-overflow fixes are still valuable as (a) proof the class
  exists in this codebase and (b) targets for any future write channel
  (root/EDL/token), where a malformed boot partition can be planted.
- Best pre-auth exploitation avenues now: **RTAS/bbauthtool parser fuzzing**
  and **getvar/oem/download probes**, plus the USB-stack audit.

## Next

1. Safe pre-auth probe batch: malformed `getvar`/`oem` arguments (lengths,
   format strings, colons) via the raw libusb harness; log anomalies.
2. RTAS protocol fuzzing using `authboot_client.py` (trigger via a gated
   command, then malform handshake fields).
3. Reboot confirmations + device liveness handling between probes.
