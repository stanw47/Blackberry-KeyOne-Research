# notes/49 — Write channel confirmed + token crypto decoded (ECDSA)

Date: 2026-10-09
Device: BBB100-3 `1164118297`, ABL766, in fastboot.
Supersedes/extends: notes/09 (write channel first seen), notes/46, notes/48; corrects
notes/15 (token crypto), `aboot-re-authboot.md` (flash gate), `aboot-re-devinfo.md`,
`docs/KEYone-research-arc.md` + README ("flash path is authboot-gated").

## 0. Incident: securewipe recurrence (2026-10-09)

`oem securewipe` was run again without re-reading notes/17 first. Same result as
2026-10-02: **boot/recovery signature records wiped** (`oem info` → "No Signature
found"), userdata wipe pending on next boot.

Immediate recovery (proven, safe):
```
fastboot flash bootsig      target/product/bbry_qc8953/sig/boot.img.production-sprint.sig
fastboot flash recoverysig  target/product/bbry_qc8953/sig/recovery.img.production-sprint.sig
```
After: `oem info` shows `ec_agent / 20181127.133122 / APBI / sprint` for boot and
recovery again; oracle MATCH (`bootsig` sha224 `72065002de83…`).

**HAZARD (repeat):** `oem securewipe` is un-gated and destroys the HLOS sig records
(and userdata). It is a recovery-flow flag-setter, not an exploit surface (notes/17).
Never run it without re-reading notes/17.

## 1. THE WRITE CHANNEL — partition-class permissions (live, 2026-10-09)

`flash:` is **per-partition gated, not globally type-1** (live falsifies the
simplified reading of the notes/aboot-re-authboot.md whitelist table):

| command (packaged BB fastboot) | result |
|---|---|
| `erase cache` | **OKAY** |
| `flash tz` | **OKAY** |
| `flash boot` | **OKAY** |
| `flash recovery` | **OKAY** |
| `flash aboot` | **OKAY** |
| `flash sbl1` | **OKAY** |
| `flash bootsig` | **OKAY** |
| `flash recoverysig` | **OKAY** |
| `flash persist` | **FAILED** (`authboot flash permission denied`) |

- Same denial for `persist` via packaged `fastboot.exe`, BlackBerry `authboot.exe`,
  and clean `adb reboot bootloader` flow. `oem securewipe` also ran un-gated.
- `system/userdata/oem/modem/dsp` were flashed OKAY during the 2026-10-02
  autoloader restore (notes/17); not re-tested today.
- **Note the distinction:** the *write* layer is open for boot-chain-class
  partitions; the *boot* layer enforces ECDSA (below). notes/09's
  "only lets you overwrite with signed images" was wrong at the write layer:
  any bytes can be written — they just won't pass boot verification.

### Arbitrary write proof (oracle round trip)

```
stock boot.img sha224      7e3c8cd1a8e16e08090c6d9be466972d0775dacc98ab4b1111a0479a
modified (64 B @0x0F4240)  ac43fb8b8f1378a249d76c833d2d06bf48590968627be774d054f42a
flash boot <modified>      OKAY
oem parthash:boot 29011968 = ac43fb8b…  MATCH modified file
flash boot <stock>         OKAY
oem parthash:boot 29011968 = 7e3c8cd1…  MATCH stock file
```

Tool: `tools/parthash.py compare boot <file>` (pre-auth SHA-224 oracle, notes/48).

## 2. HLOS token format + `verify_hlos_image`

208-byte sig record (`bootsig` / `recoverysig`; `sig/*.sig`):

```
0x00 magic  530bf50e  (LE 0x0EF50B53 — same constant checked at 0x8f653c44)
0x04 Name   16 B  "ec_agent"
0x14 Time   16 B  "YYYYMMDD.HHMMSS"
0x24 ID     16 B  "ADBI" | "ABBI" | "APBI" | "ACBI"
0x34 Tag    16 B  e.g. "sprint"
0x44 sig   ~140 B  ECDSA signature blob (+ sizes; curve/format per aboot crypto lib)
```

- Device's records are **`production-sprint`** (`20181127.133122`, ID `APBI`,
  Tag `sprint`); device `bootsig` content == package
  `sig/boot.img.production-sprint.sig` (sha224 `72065002…`). notes/48's
  "differs from package" only meant it differs from the *generic* `boot.img.sig`.
- `boot.img` and `recovery.img` are byte-identical in ABL766 (same token file too).

`verify_hlos_image` @ `0x8f653c38`:

1. No magic → print `Signature not found!` → fail (unless bypass below).
2. Secure check `bbry_is_secure` (0x8f654f88): insecure → print
   `Ignoring auth failure on insecure device` → **return 1 (boot)**.
3. `dbg_token_is_unsigned_hlos_allowed` (0x8f63c694): active `/nvuser/hlos_unsigned.tkn`
   → print `Debug token hlos_unsigned is active. Skipping image verification failure.`
   → **return 1 (boot any image)**.
4. Strict path: hash(**image bytes + 72-byte token header**) → ECDSA verify
   (0x8f653b4c → 0x8f66ea2c) against the per-ID public key compiled in aboot:
   `ADBI` @ `0x8f6e12e8`, `APBI` @ `0x8f6e1370`, `ABBI` @ `0x8f6e13f8`,
   `ACBI` @ `0x8f6e1480` (each 0x88-byte struct; header is a SEC1 uncompressed
   point `04 || X || Y` with 32-byte coordinates — ECDSA-256 family; the struct
   carries additional fields, exact layout TBD).
5. Post-crypto policy checks (`is_mfi` @ 0x8f653dd4, ID/name/time checks) → pass
   or fail (`Invalid key ID`, `Sig info: …`, etc.).

So the write channel cannot boot a modified image without either a valid
signature or the insecure/hlos_unsigned bypass.

## 3. Token crypto = ECDSA with keys compiled into aboot

The debug-token/RTAS record verifier is **not** HMAC/RSA (correcting notes/15):

- `nvverify_verify` / RTAS record verify @ `0x8f657c3c`: magic `0xae104a54`,
  version ≤ 2, length check; RTAS context init `0x8f659958` prints
  `RTAS initialize context` / `Could not find RTAS key for tool %s`;
  record is **BSN-bound**, some blobs encrypted ("Failed to encrypt the blob").
- Tool name is built at runtime from the device's own BSI tags
  (`product` / `variant`, getters `0x8f63a844`) as `<TOOL>-<product><variant>`,
  e.g. `DBGSIG-bbb100usa`, then looked up (`0x8f65a270` → `0x8f65a1e8`) in a
  **55-entry table at `0x8f794988`**, entry format (20 B):
  `{name_ptr, strlen, type=1, key_ptr, 0x88}`; key blobs are SEC1 uncompressed
  points (`04 || X || Y`; e.g. `AUTHBOOT-bbb100usa` @ `0x8f6e2b34`: `04 01 4e08…`).
- Tools: `AUTHBOOT`, `DBGSIG`, `DDT`, `NVSIG`, `STP`. Variant sets per build:
  AAK399 3 (emea/global/usa) → AAL093 4 (+cn) → AAN355 13 (+dscn/india/japan/
  bbd100×5) → ABL766 12 (india dropped, bbd100 retained).
- ECDSA verify core `0x8f6580e8`; the strings notes/15 took for keys
  (`0x8f6e2568`, `0x8f6df098`) are the **`DBGSIG` / `NVSIG` name strings**, not
  key material. There is **no symmetric key, no writable key store** — private
  keys are BlackBerry HSM-held.

**Verdict: forging `hlos_unsigned.tkn` / bootsig records is cryptographically
blocked.** Remaining routes are parser bugs in the record path or the classic
bootloader-exploit route.

## 4. MFI cross-check (notes/12/14 stand)

`is_mfi` is consulted inside `verify_hlos_image` only **after** successful crypto
(0x8f653dd4, policy layer). The MFI pairing (signed boot image with
`androidboot.imagetype=mfi` DTB cmdline) is not a verification bypass. No change
to notes/12/14 conclusions.

## 5. Recovery / verification procedures

- Restore sig records: `flash bootsig`/`flash recoverysig` (files above), verify
  with `oem info` + `tools/parthash.py compare bootsig <file>`.
- Full restore: ABL766 `flashall.bat` (aveflash.lua) — works on this unit
  (2026-10-02 precedent, all images OKAY).
- Verify any write: `tools/parthash.py compare <partition> <file>` (pre-auth).
- Current device state after this session: stock images + `production-sprint`
  tokens restored; **pending userdata wipe** from today's securewipe may fire on
  next boot.

## 6. What this changes for the unlock hunt

- The primitive we wanted (arbitrary partition write) **exists**, but boot
  requires an HSM-signed token. Token/key parsing is the only remote surface.
- Next options (ordered by risk):
  1. Fuzz the reachable record/verify path live by flashing crafted
     `bootsig`/`recoverysig` + modified `boot` (fully restorable; see recovery).
  2. Downgrade to an older signed bootchain (AAK399/AAN355) and exploit the
     pre-2018 aboot parser bugs (notes/45/46 fix list) — brick risk (rollback).
  3. Thin chance: any leaked per-variant `DBGSIG`/`APBI` private key.
