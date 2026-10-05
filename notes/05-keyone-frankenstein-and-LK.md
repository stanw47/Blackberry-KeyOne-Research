# KEYone (BBB100-3 Sprint) — Frankenstein/Oreo Feasibility & LK Bootloader Analysis

Date: 2026-10-02
Device: BlackBerry KEYone BBB100-3 (Sprint/CDMA), build ABL766, Android 7.1.1
Firmware analyzed: `emmc_appsboot.mbn` (LK bootloader) from ABL766 autoloader

## Headline

**Frankenstein "upgrade to Oreo" is theoretically possible (identical MSM8953 hardware
across KEYone variants) but blocked by the SAME permanent-write-protect wall already
documented for BB10 in the main repo.** The boot partition is `bbss_wp_type=permanent`,
secure boot enforced, and the LK bootloader performs signed verification via TrustZone.

## Why the -3 specifically never got Oreo

- TCL/Sprint **never shipped an Oreo build for BBB100-3 (CDMA)**. CrackBerry confirmed:
  "Sprint BlackBerry KEYone will not be getting Android Oreo" and the community
  ambassador: "You have the Verizon phone... You can't apply the generic version either."
- The OTA/autoloader system is **PRD-gated** (mbirth.uk research): the 5 middle digits of
  the PRD must match. `-3` = PRD-63118; `-1` = 63116; `-2` = 63117. Different families.
- No CDMA Oreo modem stack was ever produced; `-1`/`-2` Oreo builds carry GSM modems.

## Hardware identity (supports "frankenstein is physically possible")

| | KEYone -1 / -2 / -3 |
|---|---|
| SoC | MSM8953 / SD625 (all identical) |
| GPU | Adreno 506 |
| Keyboard | stmpe-keypad |
| Panel | Livata DSI |
| Fingerprint | goodix |
| LED | fan5702, ktd2026 |

A `-1`/`-2` Oreo `system`+`vendor` image *can* physically boot on `-3` silicon. The blockers
are purely security/lock, not hardware.

## The blocker (verified live)

```
ro.boot.binfo.bbss_wp_type   = permanent    <-- eMMC boot region hardware WP
ro.boot.binfo.bbss_insecure  = false
ro.boot.flash.locked         = 1
ro.boot.veritymode           = enforcing
ro.boot.binfo.primary_bc_ver = ABL766
```

`bbss_wp_type=permanent` is BlackBerry's own Android-side secure-boot field, analogous
in spirit to the BB10 boot-partition write-protect. (The BB10 Passport's boot partitions
are in fact `B_PWR_WP_EN` — a power-on/temporary protect that software cannot clear — not
a fused `B_PERM_WP_EN`.) The KEYone Android bootloader reuses BlackBerry's `bbss`
(BlackBerry Secure Boot Signature) design.

## LK bootloader reverse-engineering (emmc_appsboot.mbn)

- Format: **Qualcomm MBN-wrapped ELF32 ARM**, 1,952,062 bytes
- Loads at **paddr 0x8F600000**, file offset 0x8000, filesz 0x1A526C
- It is **LittleKernel (LK)**, BlackBerry-customized with an auth layer.

### Present security functions / strings (file offsets)
```
0x0dec6c  "Device is unlocked! Skipping verification..."      <-- the bypass target
0x0de8f1  "get_unlock_ability: %d"
0x0df954  "oem unlock is not allowed"
0x0e092c  "oem unlock"
0x0e0938  "oem unlock-go"
0x0e8f60  "Insecure bootchain detected. Skipping fuse verification check"
0x0db6ec  "scm call to check secure boot fuses failed"
0x0e9110  "Image verify failed"
0x0ea5b8  "Failed to Verify ECDSA signature"
0x0de844  "boot_linux_from_mmc"
0x0de858  "boot_linux_from_flash"
0x1d06af  "image_verify_with_key"
0x1d5372  "image_verify"
0x1d56b6  "verify_hlos_image"
0x1d6cf0  "fuse_verify"
0x1d29dd  "boot_verify_keystore_init"
0x0f564c  "dm-verity_device_corrupted"
```

### BlackBerry-specific additions (not in stock LK)
- `bbry/cmdline/cmdline.c`, `bbry_update_cmdline`, `get_cmdline_from_token`
- `bbauthtool`, `rtas_verify_response`, `rtas_verify_nv_sig_response`
- `nvverify_verify`, `nvverify_verified_read`, `nvverify_verify_all_required_recs`
- `fuse_verify`, `sb_ecc521_verify_sign` (P-521 ECDSA)
- `verify_hlos_image`, `boot_verify_keystore_init`
- `Insecure bootchain detected. Skipping fuse verification check`

The last one is the LK analogue of BB10's `bbss.insecure` — the keystone the whole
secure-boot chain hangs off. If it could be set, fuse verification is skipped.

### Relevant LK CVEs (the KeyOne attack surface)
- **CVE-2013-2598** — LK `aboot.c`: overwrite signature-verification code via crafted
  boot-image load-destination header values (memory write into bootloader memory).
- **CVE-2014-0973** — LK `image_verify.c`: digest-size not validated against
  RSA_public_decrypt spec → bypass boot-image auth via trailing data.

Both target the LK `boot_linux_from_mmc` / `image_verify` path, which this binary has.
Whether BlackBerry patched them must be determined by disassembly.

## String referencing note

The `printf`-style strings are indexed via a **relative pointer table** (base ~0x8f6d6000,
pool at file 0x031xxx and 0x0de05x). Direct VA dwords are absent, so call-site mapping
needs the LK format dispatch logic. Practical exploitation would instead target the
function offsets directly (`image_verify` @ 0x1d5372 file offset is the key one).

## Conclusion / recommended path

1. **Pure software frankenstein (locked bootloader): will NOT work.** Signed boot chain +
   PRD gating + permanent boot WP reject foreign images.
2. **If unlock achieved:** an Oreo (or better, LineageOS) `system`+`vendor` from `-1`/`-2`
   could boot on `-3`, keeping `-3` modem/NON-HLOS. Cellular likely broken (CDMA modem vs
   GSM RIL). Still gated on unlock.
3. **Real unlock paths (in order of realism):**
   a. **EDL + signed firehose** (`prog_emmc_firehose_8953_ddr.mbn` — now extracted) to
      read/write partitions, test a patched `devinfo`. No desolder.
   b. **eMMC ISP / chip-off** to defeat the permanent boot WP (the only fully confirmed route).
   c. **LK exploit research** (CVE-2013-2598 / CVE-2014-0973) against `image_verify` /
      `boot_linux_from_mmc` — a *keyone-specific* unlock if unpatched.
4. **Better end goal than Oreo:** skip Oreo entirely; if unlocked, port LineageOS on the
   published `msm8953/ABY299` kernel using `-3` blobs → modern Android, not 8.1.

## Files

- `firmware/keyone-abl766/.../emmc_appsboot.mbn` — LK bootloader (analysis target)
- `firmware/keyone-abl766/.../sbl1_signed.mbn`, `tz.mbn`, `rpm.mbn`, `devcfg.mbn`
- `firmware/keyone-abl766/.../qcbc/fh/prog_emmc_firehose_8953_ddr.mbn` — EDL loader
- `tools/lk_analyze.py` — LK MBN/ELF string + reference analyzer
