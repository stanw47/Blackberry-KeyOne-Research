# notes/53 — Factory mode / MFI linkage + authboot permission model (live + static)

Date: 2026-10-09 (live session: backup chain AAK171, then primary ABL766)
Related: notes/12 (nvverify/MFI branch), notes/14 (MFI pairing), notes/49
(write channel), notes/52 (sandbox).

## Why factory mode was pursued

KEY2/kibo precedent: FACTORY_MODE + modded boot image → flash/verify bypass.
Question: does factory mode do anything on the KEYone (LK), and is it settable?

## 1. It is the MFI gateway (static, decisive)

`set_is_mfi` (0x8f6550a0 region) logic:

```
is_mfi_var (0x8f7bebd8) default 0
if strstr(cmdline, "androidboot.imagetype=mfi"): is_mfi = 1
if get_bootmode() != 0:                 # PRODUCT
    return                               # sfi/mfi as found above
else:                                    # FACTORY (mode 0)
    if !strstr(cmdline, "androidboot.imagetype=sfi"): is_mfi = 1
```

- Boot mode values: **0 = FACTORY_MODE, 1 = PRODUCT_MODE** (`set_bootmode`,
  0x8f64b104; strings `FACTORY_MODE`/`PRODUCT_MODE`).
- Factory mode + a boot image whose cmdline lacks `sfi` ⇒ **is_mfi = 1** ⇒
  `boot_linux_from_mmc` takes the MFI path (notes/12) and `verify_hlos_image`
  has the MFI policy branch (0x8f653dd4, post-crypto).
- **Cmdline sources are all signed/RPMB**: boot image (ECDSA-signed), BSI tags
  (`add_to_cmdline_from_bsi`, RPMB-backed), tokens (`get_cmdline_from_token`,
  ECDSA-signed). No writable injection source found.

## 2. Boot mode storage is RPMB

- `set_bootmode` writes record `BOOT_MODE_TYPE` via **`rpmb_write_record`**
  (0x8f671f6c) — i.e., TZ/RPMB-authenticated; not plain flash.
- Handlers hardcode the mode: `cmd_oem_set_product_mode` → `set_bootmode(1,0)`;
  `cmd_oem_set_factory_mode` → `set_bootmode(0,0)`. No argument injection.
- Callers of `rpmb_write_record`: `set_bootmode`, `set_bootmode_count`,
  `write_bl_rpmb_entry` (blocklist). No un-gated user-reachable writer found.
- Live: in the backup chain AAK171, `oem set-product-mode` → **OKAY**;
  `oem set-factory-mode` → `authboot command permission denied`.

## 3. Authboot whitelist table (dump @ 0x8f6de194, 38 × 16 B)

Fields: {name_ptr, type, 0, flag}.

```
flash: type1 | erase: type1 | download: type1 | getvar: type0 | reboot type0
reboot-bootloader type0 | continue type0 | oem securewipe type0 | oem setprd: type9
oem enable-usb-reset type1 | oem led: type1 | oem setled: type1
oem erase-ddr-training-primary type1 | ...-backup type1 | oem enable-usb-shutdown type0
oem info type0 | oem bootmetrics type9 | oem enable/disable-charger-screen type9
oem console type9 | oem mmcinfo type8 | oem parthash: type1* | oem ddrinfo type8
oem bootlog type8 | oem grswipe type4 | oem getvarp: type2 | oem read: type8
oem dmesg type8 | oem blocklist-wipe type3 | oem mmchealth type8 | oem gptinfo type3
oem format type3 | oem set-factory-mode type6 | oem set-product-mode type1*
oem clear-lal type8 | oem test-ddr type3 | oem bide-storage-wipe type3
oem clear-anti-theft type5
```

`*` = type 1 in the table but allowed live → the RTAS service policy is what
actually decides per command string.

- Lookup is **exact match** (`get_perm_item`: strncmp over entry + strlen
  equality) — no prefix/partial differential.
- Type 0 = always allow; types 2..10 map to RTAS codes 0x1000..0x1008
  (`rtas2_cmd_authorization_check`); type 1 uses code 0.
- `authboot_check_partition_permission` (0x8f638040): in **FACTORY mode**, a
  5-entry fast path allows only the hidden factory regions:
  `phyboot0`, `phyboot0hwi`, `boot0hwi`, `phyboot`, `phyboothwi`.
  In PRODUCT mode it normalizes `debug_token:`→`debug_token` and defers to the
  RTAS service.
- The RTAS service denies `flash:persist` and `oem set-factory-mode`, allows
  `flash:boot` etc. — policy lives device-side (bbauthtool/TZ), not in LK.

## 4. Verdict and consequences

- **Factory mode is the real KEY2-style gateway on the KEYone too** (factory +
  non-sfi image ⇒ MFI lenient path) — but it is **RPMB-backed and the only
  setters are gated commands or code paths unreachable pre-auth**.
- No string/case/prefix differential found in the permission checker;
  `set_product_mode` writes only PRODUCT.
- Therefore: reaching factory mode requires **code execution in aboot**
  (to call `set_bootmode(0,0)` / set `is_mfi_var`) — the same generic
  requirement as before, now with a very concrete target (two globals/branches).
- Post-root alternative (Android): with kernel root, the BB Android services
  (`mfgUtil`, `bcc`/`tctd`, `secsvr`, `bb_tokenserviced`) may be reachable to
  request factory mode from TZ; direct partition writes also become possible
  (except RPMB-backed records). This keeps KGSL (notes/24–32) as the flagship
  path to root.

## 5. Evidence

- Live probes: `oem set-product-mode` OKAY (AAK171), `oem set-factory-mode`
  denied (both chains); getvar bootmode: PRODUCT_MODE.
- Static: symbol table parsed (pyelftools); disasm of `set_is_mfi`,
  `set_bootmode`, both cmd handlers, `authboot_check_command_permission`,
  `get_perm_item`, `authboot_check_partition_permission`; whitelist table dump.
