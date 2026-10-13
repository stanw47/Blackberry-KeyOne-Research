# 70 — verify bypass confirmed; boot-time writable surfaces mapped (vendor region, FFBM misc, wipe semantics)

Date: 2026-10-13 (session 70)

## 1. THE BYPASS, confirmed at instruction level

`verify_hlos_image` (0x8f653c38): on ANY failure (bad magic / sig not found /
`image_verify_with_key` fail / subvariant tag mismatch) the error code is set,
then:

```
8f653c80: bl bbry_is_secure
8f653c84: cmp r0, #0
8f653c88: beq 8f653d5c          ; insecure -> "Ignoring auth failure on insecure device" -> return 1 (PASS)
```

- `bbry_is_secure()` (0x8f654f88) = `1 - [0x8f79488c+0x18]` (the flag set by
  `bbry_target_hwi_init` when `bsi_get_data("bbss_insecure") == "true"`).
- Strings: `"Ignoring auth failure on insecure device"` @0x8f6e1268,
  `"Debug token hlos_unsigned is active. Skipping image verification failure."` @0x8f6e1294.
- Also `boot_linux_from_mmc` has multiple insecure-mode branches (8f62acb4 path,
  factory-mode continue at 8f62a5fc..8f62a610, blocklist skip, etc.).
- So: **bbss_insecure=true in the bsi store == unsigned HLOS boots.**

## 2. Store provenance — still unresolved

- aboot reads the bsi store from **SMEM entry 0x87**: `bbry_target_hwi_init`
  (0x8f6547fc) → `smem_get_alloc_entry(0x87)` → `bsi_init` (0x8f63a7f8 = ts_init)
  → cached at [0x8f7bdfc4]; `bsi_get_data`/`bsi_update_tag` wrap ts_get_data/ts_update_tag.
- SBL1 publishes its store to SMEM 0x87: `FUN_080265a4` (via `FUN_08026628`,
  boot_smem) copies store→SMEM entry 0x87 (0x2000 B), repoints store there,
  adds `"backup_bootchain"` (= byte 0x805b001 = param_2).
- SBL1 store pointer (0x805b844; wrappers FUN_08026f64/74/8c/fa4) is set ONLY by
  `FUN_08026f8c`; callers: `FUN_080265a4` (SMEM) and `sbl1_mc FUN_08043248`
  (**param_3 = r2 from PBL entry @0x80091c0**, ELF entry — r1/r2 untouched by entry).
- SBL1 has **no HWI text parser** (no chksum/FNV/parse strings), no boot0/hwi/bbss
  partition names, and never sets product/variant/bbss_insecure (all 32
  FUN_08026fa4 call sites = DDR/PMIC/version/backup/PON tags). AAK399 SBL1 (2017-04)
  has same bbss_insecure/backup_bootchain strings but not even product/variant getters.
- Live read of SBL1/PBL memory: not possible (no UART; block devices + /nvram denied
  to shell AND priv_app; `oem read:`/`oem bootlog` RTAS-gated).
- Store (ts) format: `[u32 used][u32 capacity][u16 ?][u16 count][entries]`;
  entry = `[u16 size][u16 namelen][value][name]` (name NUL-padded to namelen).
  Live store has 3 entries in the boot.img vendor region (below).

## 3. NEW surface: the boot.img "VENDOR!?" payload

- boot.img layout: header page (0x800) + kernel + ramdisk + second; signed content
  ends exactly at the vendor region (stock: 0x1BAA800). Tail = `"VENDOR!?"` +
  `u32 hsize` + ts store (stock: hsize 0x71F, 3 entries).
- Read at boot by `boot_linux_from_mmc` → `bbry_get_vendor_hsize` (0x8f631054:
  magic at img_end-12) + `bbry_vendor_payload` (0x8f6310c4: mmc_read tail,
  magic check, ts_init, dispatch table @0x8f6d95e0):
  - `"blocklist"` → `fill_blocklist_from_vendor` (0x8f636c9c) — globals for process_blocklist
  - `"blocklist_certificate"` → same
  - `"TARGET_BUILD_VARIANT"` → `set_target_build_variant_from_vendor` (0x8f6552cc):
    `"user"`→1, `"userdebug"`→2 → [0x8f7bebdc]
  - `"binfo"` → `init_binfo_from_vendor` (0x8f630e64): nested store, entry keyed by
    product+variant+subvariant (e.g. `bbb100cnchina`) → comma blob
    `builtby=JDM,model=...,model_num=...,oem_tag=...,product=bbb100,simcount=1,svnumber=N`
- Consumers: `get_binfo_from_vendor` → cmdline `androidboot.binfo.model/model_num/
  svnumber/builtby/simcount/oem_tag`; build variant gates `androidboot.adb.mode=enable/
  disable`, `loglevel`, `debug_extra`, `enable_battery_log`, and `wp_emmc_user` in target_uninit.
- **ANSWERED (static, definitive): the vendor payload IS covered by the signature.**
  boot_linux_from_mmc computes the verify size r9 = page + align(kernel) + align(ramdisk)
  + align(dt) + **align(vendor_hsize)** + align(second) — traced at 8f62a444..8f62a4a0
  (`add r1, sl, r1` includes the vendor) — = 0x1BAB000 = the exact file size (with
  vendor_hsize 0x72B → aligned 0x800). The same r9 is used to read the image
  (mmc_read of r9-page bytes at 8f62a53c) and as the SHA512 size in
  verify_hlos_image → image_verify_with_key (0x8f653b4c: SHA512_Update(data, size=r9)
  + SHA512_Update(header,72) → ECDSA521). The stock image verifies ⇒ the signature
  covers the vendor store ⇒ modifying it breaks verification. The vendor region is
  NOT a writable surface. (recovery.img is byte-identical to boot.img, md5
  deac36ac66f36caff4a8468bfb65158f.)

## 4. NEW surface: misc `"ffbm-XX"` → Android FFBM factory mode

- `boot_linux_from_mmc` calls `get_ffbm` (0x8f630c84): reads misc page 0; if it
  starts with `"ffbm-"` → strlcpy to [0x8f7ba240], sets flag [0x8f7ba204]=1 →
  `update_cmdline` appends `" androidboot.mode=<ffbm string>"`.
- Android init: `ro.boot.mode` ffbm* → **FFBM factory mode**:
  `"Booting into ffbm mode"`, `"ffbm mode, not start class main"`,
  `"fs_mgr: ffbm mode,skip mount userdata"`; /data = tmpfs; factory services
  (mmi/root, ptt_ffbm/root, tftp_server, qcom-c_main-sh, irsc_util, qcamerasvr,
  qcomsysd, wcnss-service, rmt_storage, per_mgr); `sys.usb.config=diag,adb`;
  `/factory/factory.prop`.
- `init.qcom.factory.rc`: `on property:sys.boot_mode=ffbm → write misc "ffbm-01"`;
  `...normal → write misc "normal"` (factory writes misc itself).
- misc = LUN0 p35, type 0xa (RTAS-gated for direct flash) but writable via meta
  bypass. **Safe + reversible.**

## 5. Fastboot tables fully enumerated

- Standard table (20): flash: erase: continue reboot reboot-bootloader oem unlock
  oem unlock-go oem lock flashing unlock/lock/lock_critical/unlock_critical
  flashing get_unlock_ability oem device-info preflash oem enable/disable-charger-screen
  oem off-mode-charge oem select-display-panel.
- BBRY registrations (27): oem parthash: oem mmcinfo oem enable/disable-charger-screen
  oem info oem bootlog oem securewipe oem blocklist-wipe oem grswipe oem enable-usb-reset
  oem enable-usb-shutdown oem led: oem setled: oem setprd: oem clear-anti-theft oem format
  oem gptinfo oem set-factory-mode oem set-product-mode oem erase-ddr-training-primary/backup
  oem getvarp: oem read: oem mmchealth oem console oem clear-lal oem bide-storage-wipe.
- Partition permission table @0x8f6ddb10 (67 entries `{name,type,wipe_mask,flags}`):
  - type 1 (pre-auth flashable): pmic hyp sdi devcfg aboot sbl1 xbl rpm tz system modem
    boot bootsig recovery recoverysig oem oemspare userdata cache dsp oempersist
  - type 0xa (RTAS): gsign blog perm ddr ddrbak bkup_ddr prdid prdidsig boardid boardidsig
    rcause ares tar rfcal1 rfbackup misc keystore partition gpt partitionforce nvuser
  - type 3: sec crypto ssd metadata config boot0hwi phyboot0 phyboot0hwi phyboot1 phyboot1hwi
    phyboot phyboothwi validate_bsis_seed
  - type 4: fsc modemst1 modemst2 fsg persist bbpersist; type 5 frp; type 7 debug_token,
    all_debug_tokens; type 9 apdp.
- FACTORY bootmode additionally allows exact phyboot0/phyboot0hwi/boot0hwi/phyboot/phyboothwi.

## 6. set_bootmode wipe semantics (why factory mode is destructive)

- `set_bootmode(mode,force)`: PRODUCT→FACTORY = **wipe_device(32)**;
  FACTORY/EXPIRED→PRODUCT = wipe_device(16); same-mode = `"Skipping Factory transistion wipe"`.
- `wipe_device(mask)` wipes every partition whose `wipe_mask & mask != 0`
  (`wipe_partition` → is_partition_nv ? wipe_vtnv_partition : mmc_erase_card).
- wipe_device(32) (bit 0x20) hits: boot system recovery oem userdata cache modem
  rcause bcota misc frp sec prdid boardid-sigs perm nvuser carrier metadata
  bootsig/recoverysig oemspare = **full factory wipe**. Survivors: sbl1 tz rpm
  aboot devcfg pmic hyp sdi xbl ddr/ddrbak/boardid/keystore/gsign/crypto/ssd/config/
  dsp/oempersist/apdp/tar/rfcal1/rfbackup/ares/fsg/modemst1/2/fsc/persist/bbpersist.
- No `force=1` caller exists for mode 0 (only aboot_init `set_bootmode(1,1)` on
  get_bootmode()==-1). `cmd_oem_set_factory_mode` = set_bootmode(0,0)+reboot, and is
  whitelist-denied (type 6 / RTAS 0x1004).
- => factory bootmode is unreachable without (a) RTAS auth and (b) a full wipe.

## 7. Cleared / dead ends (this pass)

- `"bootselect"` partition (BSel magic, version 0x00010001, flags @+0xC) read at the
  start of boot_linux_from_mmc — **not present** on the device (56 LUN0 partitions,
  /proc/partitions NPARTS=56).
- `"Unified boot method!"` path (memcmp(0x8f6ff000,"ANDROID!")): no writer of
  0x8f6ff000 anywhere in aboot (region = ECC521 bignum data) → dead.
- `is_mfi` (`"androidboot.imagetype=mfi"`, or `"sfi"` in factory mode) read from the
  SIGNED boot.img cmdline (offset 0x40, 512 B) via set_is_mfi (0x8f655068) — not usable.
- /system = dm-0 verity (dm-0 name "system"); /oem raw ext4 (verity inactive) — unchanged.
- AAK171 backup chain not present in any autoloader (Ventoy has AAK399/AAL093/ABL766/
  AAN355 only). Its whitelist/set_bootmode remain untested — do NOT blind-fire
  `oem set-factory-mode` on the backup chain (wipe risk if it has the same transition logic).

## 8. Next options

1. **FFBM factory-mode switch**: meta-write `"ffbm-01"` to misc (p35) → reboot →
   Android factory mode. Safe/reversible (restore misc via meta + fastboot).
2. ~~Vendor-region signature test~~ — resolved statically: **signed** (see §3). No test needed.
3. **Store-source hunt**: SOLVED architecturally (session 70, Passport material): the
   boot0 `stage1` partition is the BBSS loader — it parses the HWI text
   (`hwi_parse`), `bsi_create`s the store, sets `bbss_wp_type`/`backup_bc_ver`, and
   "Jump to SBL" — passing the store pointer to SBL1 in r2 (== KEYone param_3).
   Both live on HW-WP'd boot0 → route stays blocked.
4. **FFBM path → root?**: in FFBM mode factory services run as root (mmi, tftp_server,
   ptt_ffbm, qcom-c_main-sh, ...). If any is exploitable/feedable → root on Android.
   A root process with QSEE access could theoretically re-send aboot's RPMB
   `rpmb_block_write` (secapp TA) to write the BOOT_MODE record without a wipe —
   speculative, untested.
5. Backup chain (POWER+VOL_UP) read-only probes only (`oem info`, `getvar all`).
