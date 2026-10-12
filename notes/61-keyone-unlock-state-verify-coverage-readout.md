# notes/61 — Unlock-state archaeology, image-verify coverage, and the pre-auth readout (live)

Date: 2026-10-12. Device: KEYone BBB100-3, ABL766 (fastboot 0fca:8040, serial
1164118297). Related: notes/16 (RTAS2 spec), 35 (unlock denial), 48 (parthash),
49 (write channel), 53 (factory/permission model), 59 (authboot wire live).

## 1. `is_unlocked` — already 1; we never wrote it

- devinfo (via the parthash oracle, notes/48) shows `is_unlocked=1`,
  `is_unlock_critical=0`, `is_tampered=0`, `charger_screen=1`.
- The only devinfo write attempt ever made (a no-op test: flashing the exact
  current 240 bytes) returned `authboot flash permission denied`. No devinfo
  write has ever succeeded.
- Retail ABL766 cannot set unlock itself (notes/35: `set_device_unlock(0,1)`
  always takes "oem unlock is not allowed"; only locking reaches the writer).
- Therefore the flag was set by factory/RTAS-authorized provisioning before we
  had the device. Consistent with `is_unlock_critical=0` (non-critical unlock).

## 2. What `is_unlocked=1` does — decoded

- **No verify bypass.** `verify_hlos_image` never reads devinfo; the
  "Skipping verification" consumer is dead in retail (notes/35).
- **One real boot effect:** `boot_linux_from_mmc` @0x8f62aa20 —
  `if (is_unlocked || is_unlock_critical) skip target_load_ssd_keystore()`
  → the SSD/BIDE anti-theft keystore is NOT loaded on this unit.
- `oem unlock-go` precondition only (command RTAS-denied; writer only handles
  locking).
- Net: no custom ROM/recovery (ECDSA verify), no token shortcut; the unlock is
  a provisioning artifact + a runtime anti-tamper weakening.

## 3. HLOS image verify — full decode (`image_verify_with_key` @0x8f653b4c)

- digest = **SHA-512(image[0..r9] ‖ sig_record[0..0x48])**; verify =
  **ECDSA P-521** with a 136-byte key blob (`ECC521octet2Point`).
- 208-byte sig record layout:
  `+0x00 magic 0x0ef50b53 | +0x04 name[16] | +0x14 time[16] | +0x24 id[4] |
   +0x28 tag[32] | +0x48 r[68] | +0x8c s[68]`.
- Key selection: id strcmp over a 4-entry table @0x8f6e10ac
  (ADBI/ABBI/APBI/ACBI → key blobs). Post-crypto policy: id==APBI → is_mfi
  chain; else must match the token key name; ADBI/ABBI accepted; APBI tag must
  equal `bbry_get_subvariant()` ("sprint") or the token tag override.
- Shipped variants (all valid signatures over the SAME boot.img): `.sig`=ADBI,
  `.beta`=ABBI, `.carrier`=ACBI, `.carrier-sprint`=ACBI/sprint,
  `.production`=APBI, `.production-sprint`=APBI/sprint — the device's live
  bootsig is `boot.img.production-sprint.sig` (parthash match `72065002de83…`).
  Variant swaps gain nothing (same image; policy rejects non-APBI vs token name).
- Failure path in `boot_linux_from_mmc` (0x8f62a5fc):
  verify fail + `get_bootmode()==0` (FACTORY) → **"Device is in factory mode
  continuing..."** → boots anyway; PRODUCT → "Authenticating boot image
  failed!" → -1; mode==2 → "BOOT COUNT EXPIRED !!!!!" → -1.
- `boot_linux_from_flash`'s `verify_signed_bootimg` (0x8f62b320) is a dead
  path: its `image_verify` callee (0x8f626a04) is a canary-only stub returning 0.

## 4. Pre-auth read channels

### 4a. parthash oracle — partition prefix reader (nvuser + perm extracted)

vtnvfs layout (verified against the imggen BB10 templates, structure shared):

```
0x000  defa0309 0002 0900 <4B per-image id>      header
0x03c  "nvuser"/"perm"                            partition name
0x05c  <4B per-image id>
0x200  {count u32, 0 u64, magic 0f ed de f0 + 8B} records (nvuser variant)
0x3fc..0x13fc  8 x 0x200-blocks, each ending with magic 7c 06 b1 8f
0x13fc+4        file table: entries of 0x40 bytes:
                {crc32, size u32, magic d9598dbe, type u32, 8, data_off u32,
                 id[12], name[16]}
```

- **nvuser**: exactly one file — `ramdumpinfo` (size 0x0b33). Extra records vs
  the factory template: `{0x0001000a: 0xc3a1c75c}` and `{0x0001000b: 0}`
  (template has one zeroed record). Meaning unidentified; not referenced by
  aboot code (no 0x1000a/0x1000b immediates).
- **perm**: formatted but EMPTY — no file entries, no BB10 template's
  `bootcontrolblock`. No `ddt.tkn` / `hlos_signature.tkn`.

### 4b. getvar published vars (pre-auth, command type 0)

`getvar:all` readout (live): serialno, jdm_bsn `AAKH11BPDKA00VV`,
prd `PRD-63118-003`, device `bbb100`, variant `usa`, subvariant `sprint`,
product `MSM8953`, kernel `lk`, bootmode `PRODUCT_MODE`, security `enabled`,
gpt_version `0x0005`, authboot_api_ver `2.0`, max-download-size `0x20000000`,
**is-password-set `no`**, **hlos_unsigned.tkn `disabled`**,
hlos_signature.tkn `NONE`, hlos-sig-tag `sprint`.

Publishers decoded: `fastboot_publish_token_info` (hlos_unsigned.tkn ←
`dbg_token_is_unsigned_hlos_allowed`; hlos_signature.tkn ←
`parse_hlos_signature_token` or NONE; hlos-sig-tag ← subvariant/override),
`fastboot_publish_password_set` (`password_get_type`: no / yes /
yes-non-textual / unknown), `fastboot_publish_bootmode`, `fastboot_publish_gpt_version`.

**Conclusion: this unit carries no tokens anywhere and no device password.**

## 5. Tooling + wedge mechanics (learned the hard way)

- `tools/parthash_libusb.py` — resident libusb client + resumable byte-by-byte
  parthash extraction (claim iface 0 → bulk write EP 0x01 → read EP 0x81 until
  OKAY/FAIL). ~10x faster than spawning fastboot per byte.
- WEDGE RULES:
  - **Never call `dev.set_configuration()`** — SET_CONFIGURATION disarms LK's
    fastboot endpoints; subsequent writes NAK forever (device wedged).
  - **Never kill a client mid-transfer** (partial command/response wedges the
    LK fastboot loop).
  - **Recovery: drain EP 0x81** (open + claim + read until the stuck
    `INFO…`+`OKAY` flushes) — device becomes healthy again, no power cycle.
    USB port reset does NOT recover; only the drain (or physical reset) does.
- `tools/ioctlspy.c` — LD_PRELOAD ioctl shim used to capture the stock
  fastboot binary's exact USB op sequence (CLAIM + sync BULK ioctls; libusb
  uses async URBs — both work).

## 6. "Signature transfer" analysis (user question)

- Reusing a valid signature on a modified image is cryptographically
  impossible: ECDSA over SHA-512(image ‖ 72B metadata); any change to image or
  metadata breaks it; needs a SHA-512 second preimage (~2^256). No
  length-extension (sig is over the digest, not HMAC).
- The only constructive variant: **uncovered bytes** — if any byte range that
  influences what gets booted lies OUTSIDE [0..r9], it can be modified with the
  signature intact. Open lead: r9 composition (header page + vendor hsize +
  kernel + ramdisk + …) — check whether the appended DTB (`dev_tree_appended`),
  second stage, or tail fall outside r9.
- KEY2's LineageOS route did not use signature reuse either (CVE-2021-1931
  code overwrite in ABL RAM).

## 7. Next

1. Self-signed RTAS credential experiment: drive 0x2000 handshake + 0x2004/0x2005
   with our own P-521 keypair — test whether the device validates a BB-issued
   client cert or only proof-of-possession.
2. Permission lane: session establishment without the challenge (0x1010 state
   driver); 0x1014/0x1015 "device trusts tool's answer" (commit 4aef9fd).
3. r9 coverage check (uncovered-byte reuse lead).
4. 0x2005 TLV parser deep-fuzz (notes/59 list).
