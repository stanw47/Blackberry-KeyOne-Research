# ABL766 autoloader teardown — the bootloader keys are here

Source: `/media/stanw47/Ventoy/bbry_qc8953_autoloader_user-common-ABL766.rar`
(2.09 GB RAR5, date 2018-11-20 → matches our build). Extracted with `unrar`
(7z produced 0-byte stubs). Working set under
`keyone/dumps/2026-10-02/autoloader/ABL766 - Hn03/`.

## What's inside (the important parts)

| Path | Size | What it is |
|---|---|---|
| `target/product/bbry_qc8953/qcbc/fh/prog_emmc_firehose_8953_ddr.mbn` | 340,532 | **Qualcomm MSM8953 FIREHOSE PROGRAMMER** (ELF32 ARM) |
| `target/product/bbry_qc8953/emmc_appsboot.mbn` | 1,952,062 | **LK `aboot` bootloader — NOT STRIPPED (7968 symbols)** |
| `target/product/bbry_qc8953/sbl1_signed.mbn` | 357,520 | signed SBL1 |
| `qcbc/{rpm,tz,devcfg,apdp}.mbn` | — | signed TrustZone/RPM/devcfg |
| `target/product/bbry_qc8953/gpt/rawprogram0.xml` + `patch0.xml` | — | **full eMMC partition map (EDL)** |
| `host/linux-x86/bin/authboot` | 12,062,876 | BlackBerry authboot (i386, not stripped, debug_info) |
| `host/linux-x86/bin/pcauthtool` | 638,260 | RTAS challenge/response auth tool |
| `host/linux-x86/bin/fastboot`, `adb` | — | standard |
| `boot.img`, `recovery.img`, `persist*.img`, `NON-HLOS` | ~29 MB+ | signed images |
| `sig/boot.img.production-sprint.sig` etc. | 208 | ECDSA-512 image signatures |
| `autoloader/*.lua`, `aveflash.lua`, `avecommon.lua` | — | flash logic |

## The EDL package is complete
`rawprogram0.xml` + `patch0.xml` + `prog_emmc_firehose_8953_ddr.mbn` is a
standard **Qualcomm EDL/QFIL flash package**. With a working EDL entry, QFIL or
`bkerler/edl` can read/write the whole eMMC using BlackBerry's own signed
programmer. **`devinfo` partition = start_sector 425760, 2048 sectors (1 MB)** —
the classic bootloader-unlock flag partition.

Firehose capabilities (strings): `configure`, `program`, `read`, `erase`,
`firmwarewrite`, `getsha256digest` (standard set).

## Flash method (from `aveflash.lua`)
- Default: plain **`fastboot`**; `-t` forces **`authboot`** (secure/backup-bootchain recovery).
- `-m` = `fastboot oem set-product-mode` (SWC: factory→product).
- `-c securewipe` = `fastboot oem securewipe`.
- `-c debugtokens` = `authboot debugtokens` (write BlackBerry **debug tokens**).
- `pcauthtool` only starts when a **device password is set**; it uses
  **RIMNET credentials** + an **RTAS server** challenge/response. Our device has
  no password → pcauthtool is skipped.
- `authboot_debugtokens()` warns it needs a local **"BB Tool Auth" BBToolAuth
  plugin / daemon** running — i.e. online/license authorization. **Dead end
  without BlackBerry's auth service.**

## The aboot exposes everything (not stripped)
Symbols include the whole gate:
- `authboot_check_command_permission`, `authboot_check_partition_permission`,
  `authboot_cmd_whitelist`, `authboot_ptn_whitelist`
- `cmd_oem_set_factory_mode`, `cmd_oem_unlock`, `cmd_oem_unlock_go`,
  `cmd_flashing_get_unlock_ability`, `cmd_flashing_unlock_critical`,
  `cmd_oem_devinfo`, `cmd_oem_secure_wipe`
- `dbg_token_*` family: `dbg_token_is_unsigned_hlos_allowed`,
  `dbg_token_is_console_enabled`, `dbg_token_get_selinux_mode`,
  `dbg_token_is_anti_rollback_disabled`, `dbg_token_get_pathtrust_mode`, …
- `bbry_is_secure`, `bbry_is_insecure`, `devinfo_present`,
  `ECDSA521verify`, `does_authboot_key_exist`
- EDL support: `SCM call to check dload mode`, `dload mode not entered`

This is enough to reverse the exact unlock checks and (potentially) the
`devinfo` byte format.

## Strategy (safest → boldest)
1. **Read-only EDL:** enter 9008, `edl printgpt`, dump `devinfo`/`aboot`/`boot`.
   Analyse offline. No writes.
2. If `devinfo` unlock byte is found (cf. `Giovix92/EDLUnlock`), write only that
   partition → reboot → unlocked bootloader → TWRP/Magisk.
3. Alternatively reverse `cmd_oem_unlock` / `authboot_check_command_permission`
   in the symbolized aboot for a soft path.

Tooling: `keyone/tools/edl` (bkerler/edl, venv installed).

---

## Live EDL-entry attempt (2026-10-02)

- `adb reboot edl` → device rebooted **back to Android** (no EDL). No
  `ro.boot.bootreason`; the init/aboot has no software EDL trigger.
- In fastboot, tried `oem reboot-edl`, `reboot-edl`, `oem dload`, `dload`,
  `oem edl` → all `unknown command`. **No software EDL path.**
- USB IDs observed:
  - Android/ADB: `0fca:8042`
  - **fastboot mode: `0fca:8040`** (distinct mode)
  - EDL would be `05c6:9008` (never appeared).
- **Conclusion:** EDL on this KEYone requires the **physical method** — short
  eMMC CMD/DAT0 to GND during power-up, or the factory EDL test points, or a
  "deep-flash" EDL USB cable. Then `05c6:9008` + bkerler/edl + BlackBerry's
  `prog_emmc_firehose_8953_ddr.mbn` unlocks full eMMC read/write.
