# 67 — META-IMAGE BYPASS (LIVE), HWI/BSI store decoded, boot0 WP confirmed, /oem injection surface

Date: 2026-10-12 (session 67)

## 1. THE META-IMAGE BYPASS — pre-auth arbitrary partition write (PROVEN LIVE)

`fastboot flash <any ALLOWED partition> <file>` where the file begins with magic
`0xCE1AD63C` routes `cmd_flash_mmc` -> `cmd_flash_meta_img` (0x8f62cf88)
instead of the raw-image writer. The meta container is then parsed:

```
+0x00  u32  magic 0xCE1AD63C
+0x4a  u16  entries area size = count * 0x50
+0x4c  entry[0]: name[0x48 bytes], u32 data_off @+0x48, u32 data_len @+0x4c
       entry[1] @ 0x9c, entry[2] @ 0xec, ...
       (entry[0]'s off/len are also read from +0x94/+0x98 == same fields)
data   at any absolute offset (data_off from image start)
```

Each entry is flashed via `cmd_flash_mmc_img(entry_name, data + off, len)`
**with NO partition-permission check** (the only check is the OUTER name in
`cmd_flash_mmc`, and `boot`/`system`/`oem`/... are allowed type 1).

Entry-name special cases (inside cmd_flash_mmc_img):
- `boot0hwi` (prefix)  -> `write_hwi` (boot0 GPT `hwi` text store, see §2)
- `phyboot` (prefix)   -> `write_phyboot` (software-gated: bbss_wp_type==permanent -> refused)
- `debug_token` (exact)-> `dbg_token_insert` (crypto-gated: sign() -> nvverify_verify first)
- `partition`/`partitionforce` -> set_gpt_force_upgrade(1) + raw write
- `sbl1` (exact)       -> clear_bcb_ota + raw write
- `frp-unlock` (prefix)-> refused
- anything else        -> `partition_get_index(name)` + `mmc_write` (no checks!)
- `name:lun` suffix    -> `mmc_set_lun(atoi(lun))` (LUN selection for subsequent ops)

**Live proof (device 1164118297, fastboot):**
```
oem parthash:rcause:1024  before: c12aa0dbf04d0896f986f4dd3d1e799864b1bc48245ffb5504802f07
fastboot flash boot meta_dry.img        ("writing 'boot'... OKAY")
oem parthash:rcause:1024  after:  8f4fcda4c35272b8edc481fa404026910f9ee64b4ce79bae966b3b37
```
The `rcause` partition (denied for direct flash, type 10) was written via a
`boot0hwi`... no: via a meta entry named `rcause`. Arbitrary LUN0 partition
writes from locked fastboot are now available. (First attempt with a bad
header layout silently did nothing - entries were skipped; fixed layout
above is the verified one.)

## 2. The HWI/BSI store (bbss_insecure home) - fully decoded

- The boot LUN (boot0) has its own GPT (read at byte 1024 in `write_hwi`):
  entries `hwi`, `bbss`, `stage1..3`, `sbl1r`, `tzr`, `rpmr`, `abootr`, `sdir`
  (layout confirmed on the BB10 imggen set; KEYONE checked live: `write_hwi`
  accepted the GPT and proceeded = entry0 name check passed).
- `hwi` = **4 KB TEXT store** at LBA34 (byte 0x4400) written by `write_hwi`.
- Text format (hwi_parse 0x8f63a8e4): flat `name = value` lines, comment `#`,
  charset [alnum - _], mandatory tags `product`, `variant`, `pcb_rev`,
  `pop_rev`, `bsis_type` (one of bsis_disabled/bsis_lite/bsis_pka/bsis_gv),
  plus a final line `chksum = <value>`.
- Checksum: h = 0x811C9DC5; for each line: hash name bytes then value bytes with
  `h = ((h * 0x01000193) & 0xffffffff) ^ byte`; compare parsed integer
  (cu_strtol, base auto). "Wrong checksum" if mismatch; mandatory missing ->
  "Parse error".
- Data must be < partition size and < 4095 bytes; the writer zero-pads.
- Our reconstructed text (from the live ro.boot.binfo.* props, all values
  identical to the real store) with `bbss_insecure = true` PASSED ALL PARSING
  (structure + checksum + mandatory + bsis_type whitelist + RTAS key
  AUTHBOOT-bbb100usa check + boot0 GPT magic check) and reached the final
  `mmc_write(0x4400, 4096)`:

```
fastboot flash boot meta_hwi.img
writing 'boot'...
FAILED (remote: mmc write failure[0])
```

**The boot0 write is refused by hardware write protection** (bbss_wp_type =
permanent confirmed real; aboot contains no BOOT_WP (EXT_CSD 173) switch at
all - only user-area WP functions). Boot0 path is hard-blocked as the
community record says.

## 3. Rest of the picture
- `oem unlock`/`flashing unlock` handlers exist (set_device_unlock writes RPMB
  device-info + misc "recovery\n--wipe_data" + reboot) but are command-whitelist
  denied (not in the 38-entry whitelist at all).
- `bbss_antirollback` tag is fuse-derived at boot (fuse_verify -> bsi_update_tag).
- Era diff: cmd whitelist set-factory-mode = type 6 (denied) in AAK399/AAL093/
  AAN355/ABL766 - no downgrade advantage. (Earlier conclusion stands.)

## 4. NEW: /oem partition = Android-side injection surface
- `/oem` (partition type 1, flashable) mounts **plain ext4 ro, NO dm-verity
  active** (fstab has `verify,verity_key=/addon_verity_key` but the live mount
  is the raw block device - the addon verity is inactive on this unit).
- `/oem/priv-app/*` **is scanned and installed as privileged system packages**
  (live: Gallery, Preview, TctFileManager, SprintHiddenMenu).
- ramdisk init.rc calls `validate_oem`: it fetches the `oem tag property`
  from the oem image and compares with the bootloader value
  (`ro.boot.binfo.oem_tag` vs `ro.oem.tag`). On mismatch/missing:
  **"OEM Validation Failures.., device shutting down now."** - so keep
  `ro.oem.tag = sprint` in oem.prop and any other changes pass.
- oem.prop's properties ARE applied live (ro.oem.tag, ro.oem.build_id,
  ro.product.google.services all live).
- No /oem/etc .rc imports; no /oem references in /system services; no setuid
  binaries on device; `persist.sys.tombstone.enable=*` -> suid_dumpable write
  exists but no suid process to use it on.
- `tctd` runs as root with a world-accessible (0666) unix socket - noted for
  future study.

Live pulls: `/oem` content at `~/Documents/bb-wine/keyone/oem_pull/oem`
(186 MB used / 325 MB partition). Build-tools + platform-25 downloading to
`~/Documents/bb-wine/keyone/sdk/` for the new priv-app APK test.

## 5. Recovery notes
- `fastboot flash oem <image>` (allowed) = recoverable - rebuild a clean image
  from the pulled content if needed.
- The meta bypass leaves no boot-time traces; partition writes are raw.
