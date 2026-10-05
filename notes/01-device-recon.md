# Session 01 — Device Recon (ADB)

Date: 2026-10-02
Device: BlackBerry KEYone BBB100-3 (Sprint) — serial `1164118297`

## Identity (verified live)

| Field | Value |
|---|---|
| Model | BBB100-3 |
| Product | `bbb100usasprint` |
| Device | `bbb100` |
| OEM tag / subvariant | `sprint` / `sprint` |
| Variant | `usa` |
| Board / POP | PCB-61876-001-1 rev 9 / POP-63135-001-1 rev 1 |
| HWID / DTS ID | `0xf24098b1` |
| Processor ID | `000100004C000000A6F528E8...` (MSM8953 / SD625) |
| Build ID / display id | `ABL766` |
| Fingerprint | `blackberry/bbb100usasprint/bbb100:7.1.1/NMF26F/ABL766:user/release-keys` |
| Base OS | `blackberry/...:7.1.1/NMF26F/ABI131:user/release-keys` |
| Android | 7.1.1 (SDK 25), build type `user`, tags `release-keys` |
| Security patch | 2018-12-05 |
| Build date | Wed Nov 21 04:34:17 EST 2018 |
| OEM build id | `ABD565` |
| Kernel | 3.18.31-perf-gf38c8fb, built Nov 21 04:52:44 2018 |
| Bootcount | 883 |
| Flash lock state | `ro.boot.flash.locked = 1` |
| Verity | `ro.boot.verity = active`, `veritymode = enforcing` |
| SELinux | enforcing (`ro.boot.selinux.enforcing = 1`) |
| Debuggable | `ro.debuggable = 0`, `ro.secure = 1` |

Additional traceability (from `ro.tct.*`):
- `ro.tct.curef = PRD-63118-003` (this is the PRD — confirms the `-3` being the CDMA/Verizon-Sprint SKU from the forums)
- `ro.tct.handsetref = SAA61Y3WA11C`
- `ro.tct.trace.bsn = AAKH11BPDKA00VV`
- `ro.tct.ptm = 24`, `ro.tct.trace.pth = 24`, `ro.tct.trace.pts = 194`

Board platform (build.prop): `ro.board.platform = msm8953`
Device tree path: `device/tct/mercury/system.prop`, build flavor `bbry_qc8953_sfi-user`, product `bbry_qc8953_sfi`.
Verity/recovery expected id: `ro.expect.recovery_id = 0xc0324df5513635107d83ef218095b3a138f7516c000000000000000000000000`

> Note: This build **does** have update history — `ro.build.version.base_os` = `...ABI131`, and `ro.boot.binfo.backup_bc_ver = AAK171` vs `primary_bc_ver = ABL766`.
> So it shipped ABI131/ABL766 era. It is a late-2018 (patched-era) build, NOT a launch/engineering unit.

### BlackBerry Secure Boot fields (very relevant to existing BB10 research)

```
ro.boot.binfo.bbss_insecure    = false
ro.boot.binfo.bbss_wp_type     = permanent        <-- write-protect is PERMANENT
ro.boot.binfo.bsis_type        = bsis_lite
ro.boot.binfo.primary_bc_ver   = ABL766
ro.boot.binfo.backup_bc_ver    = AAK171
ro.boot.binfo.builtby          = JDM
ro.boot.binfo.inproductionflag = false
ro.boot.system_dbg             = false
```

> The `bbss.*` (BlackBerry Secure Boot Signature) fields mirror the BB10
> `bbss.insecure` research. Here `bbss_wp_type = permanent` — BlackBerry's own
> Android-side secure-boot field. (Note: the BB10 Passport's boot partitions are
> in fact `B_PWR_WP_EN` — a power-on/temporary protect that software cannot clear
> — not a fused `B_PERM_WP_EN`; `bbss_wp_type` is a separate Android field.)

## Partition map (A-only, 56 partitions, mmcblk0)

Recovered via `/sys/class/block/*/uevent` (shell cannot read `/dev/block/by-name`).

| # | name | size (KiB) | notes |
|---|---|---|---|
| 1 | prdid | 252 | |
| 2 | boardid | 252 | |
| 3 | sbl1 | 2048 | Secondary bootloader 1 |
| 4 | rpm | 512 | |
| 5 | tz | 2048 | TrustZone |
| 6 | devcfg | 258 | |
| **7** | **aboot** | **2560** | **The bootloader (LK/ABL) — exploit target** |
| 8 | tunning | 2048 | |
| 9 | traceability | 1024 | |
| 10 | fsg | 2048 | |
| 11 | boot | 65532 | kernel+ramdisk |
| 12 | bootsig | 4 | BlackBerry boot signature |
| 13 | keymaster | 512 | |
| 14 | lksecapp | 128 | |
| 15 | cmnlib | 256 | |
| 16 | cmnlib64 | 256 | |
| 17 | modem | 98304 | |
| 18 | ddrbak | 1024 | |
| 19 | dip | 1024 | |
| 20 | mdtp | 32768 | |
| **21** | **devinfo** | **1024** | **unlock state candidate** |
| 22 | apdp | 256 | |
| 23 | msadp | 256 | |
| 24 | dpo | 8 |  |
| 25 | splash | 33424 | |
| 26 | ddr | 1024 | |
| 27 | sec | 128 | |
| 28 | limits | 32 | |
| 29 | fsc | 1 | |
| 30 | ssd | 8 | |
| 31 | modemst1 | 2048 | |
| 32 | modemst2 | 2048 | |
| 33 | oempersist | 51200 | |
| 34 | persist | 32768 | |
| 35 | misc | 1024 | BCB / slot |
| 36 | keystore | 512 | |
| 37 | config | 32 | |
| **38** | **frp** | **2048** | **Factory Reset Protection** |
| 39 | recovery | 65532 | |
| 40 | recoverysig | 4 | BlackBerry recovery signature |
| 41 | perm | 256 | |
| 42 | nvuser | 256 | |
| 43 | metadata | 1024 | |
| 44 | rcause | 16384 | |
| 45 | bcota | 12288 | BlackBerry carrier OTA |
| 46 | blog | 1024 | BlackBerry log |
| 47 | dsp | 16384 | |
| 48 | syscfg | 512 | |
| 49 | mota | 512 | |
| 50 | mcfg | 4096 | |
| 51 | hdcp | 20480 | |
| 52 | bbpersist | 20480 | BlackBerry persist |
| 53 | oem | 524288 | |
| 54 | system | 4718592 | dm-0 (verity) |
| 55 | cache | 1048576 | |
| 56 | userdata | 23719919 | dm-1 (FBE/crypt) |

Observations:
- **No `_a`/`_b` suffixes** → A-only (simpler flashing than KEY2's botched A/B).
- Bootloader lives in **`aboot`** (2.5 MiB). Size is consistent with a UEFI **ABL**
  rather than the older ~1 MiB LK. To be confirmed by inspecting the binary.
- Dedicated `bootsig` / `recoverysig` partitions = BlackBerry signature blocks.
- `devinfo` + `frp` present (standard Qualcomm).

## USB / modes

| Mode | VID | PID | Notes |
|---|---|---|---|
| ADB (Android) | 0x0FCA | **0x8042** | `adb devices` OK; `BlackBerry BBB100-3` |
| Fastboot | 0x0FCA | **0x8040** | **Identical to FakeShell KEY2 PoC** |
| Loader/other seen historically | 0x0FCA | 0x8001, 0x8017, 0x8030, 0x8031, 0x8032, 0x803A, 0x8041 | from PnP cache |

Fastboot interface descriptor (read via libusb/pyusb, no driver bound):
- Interface 0: class 0xff, subclass 0x42, protocol 0x03, 2 bulk endpoints (0x81 IN / 0x01 OUT), 512-byte.
- Interface 1: class 0xff, subclass 0x02, protocol 0xff, bulk 0x82/0x02.

## Windows driver situation (solved)

- Default: fastboot interface `0FCA:8040 MI_00` has **no driver** (problem code 28).
  `fastboot.exe` sees nothing; pyusb enumerates but `set_configuration()` errors out.
- **Fix applied:** installed **Zadig 2.9** (WinUSB via libwdi) onto `0FCA:8040 MI_00`.
  After binding, the interface shows `Driver=libwdi (fastboot (Interface 0))`, Status OK.
- Note: Google `fastboot.exe` still didn't use it directly; drive it via **libusb**
  (`tools/fastboot_libusb.py`) instead.
- **Linux works cleanly** (user's normal workflow). Prefer Linux for fastboot/exploit work;
  treat Windows as a secondary path.

### Fastboot endpoint hang (important observation)

After Zadig binding, the first libusb write to the fastboot OUT endpoint went through,
but the bootloader **never replied**, and after that the OUT endpoint NAK'd every
subsequent write (even 1 byte), surviving `clear_halt` + `usb.reset()`. Only a physical
reboot cleared it. Likely the bootloader was left mid-command (waiting on a proper
terminated command / had an outgoing response the host never drained). **Lesson:**
- BlackBerry fastboot here may need a specific terminator; don't leave a command half-sent.
- Always have a physical reboot path; a wedged ABL is not recoverable from software.

## OS-side security architecture (live-verified)

### Kernel
- `Linux 3.18.31-perf-gf38c8fb #1 SMP PREEMPT` (gcc 4.9, Nov 21 2018)
- `/proc/kallsyms` present but **addresses zeroed** (`kptr_restrict`)
- `/proc/modules`: only `wlan` (qca) module loaded
- **No `/proc/config.gz`**
- **PaX/grsecurity present** — `/proc/<pid>/status` shows `PaX: PemRs` (same hardening
  family as the Priv; references the priv kernel grsecurity work in the BB10 repo)

### BlackBerry LSM/daemons (very relevant to existing Priv research)
- **BIDE** is active: `com.blackberry.bide` PID 2523, UID **8000**, 13 threads, PaX'd
- BIDE is a **char device**: `/dev/bide` = major **229**, minor 0
  (`/sys/devices/virtual/bide/bide/{dev,uevent}`, `DEVNAME=bide`)
- `bbauthtoold` PID 520, UID **2911**, groups `1026 2900 2908 2909 2998` (PaX'd)
- Running services (`getprop init.svc.*`): `tctd`, `token_service`, `vtnvfsd`,
  `vtnvfsd_blog`
- Binder services: `bb.nfc`, `bbry_device_policy`, `trust_zone`, `password_manager`,
  `backup_token`, **`TokenService`** (`com.blackberry.tokenservice.ITokenService`),
  `android.security.keystore`, `mdtp` (Qualcomm secureMSM)
- Daemons/binaries present: `bb_tokenserviced`, `bbauthtoold`, `vtnvfsd`,
  `vtnvfsd_wrapper`, `dcmd`, `secsvr`, `tctd`, `bcc`, `bdt`, `mfgUtil`,
  `StoreKeybox`, `RetainsDataSpace`, `bkup_bc_update`, `powerup_reason`, `reset_cause`
- Libs: `libbb_tokenservice.so`, `libbbauthtool.so`, `libsecureservice.so`,
  `libbidejni.so`, `libbbry_vs.so`, `libbbusb.so`, `libbb-nfc-nci-nxp.so`
- Pulled to `recon/bin/` for offline RE

### SELinux
- **Enforcing**; policy dumped to `recon/selinux_policy.bin` (368,451 bytes)

### /nvram virtual filesystem (BlackBerry, fuse)
Mounted via `vtnvfsd` as fuse, owned by uid/gid 2900:
- `/nvram/blog` (`vtnvfs_blog_file`) — read/write
- `/nvram/nvuser` (`vtnvfs_nvuser_file`) — **read/write**  ← same target as Priv `nvuser` research
- `/nvram/perm` (`vtnvfs_perm_file`) — read/write
- `/nvram/boardid`, `/nvram/prdid` — read-only
- Backing partitions: `nvuser`, `perm`, `boardid`, `prdid`, `blog` (see partition map)

### /oem (addon verity)
- `/oem/oem.prop` → `ro.oem.tag=sprint`, `ro.oem.build_id=ABD565`
- `/oem/oem_sprint_context.txt` leaks the **addon_verity build config**, including:
  - `verity_key=/oem` block device, ext4
  - `verity_fsigner_csk_passwd=PcrDmR@3` (build-time signing password, low value but notable)
  - `verity_fsigner_keyname=APVM`, `verity_fsigner_sign_type=production`
  - public/private key **paths** on the build host (`ec_agent@br602cnc`)

### Root status
- No root: `su` absent, no Magisk/SuperSU/KingRoot installed
- Shell can read many things but `/dev/block`, `/sys/fs/pstore`, `/nvram/*`, `dmesg`
  (partial), and `/proc/<pid>/mem` are restricted by SELinux
- `dmesg` does leak runtime lines and shows **`[BIDE] INF: Updating pid(...)`** activity

## Firmware / update state

- `ro.build.version.base_os` = `ABI131`; `primary_bc_ver=ABL766`, `backup_bc_ver=AAK171`
- Security patch 2018-12-05 → **post-launch, patched-era** (not an engineering unit)
- Implication: the "KEYone was unlockable before a patch" lead likely does **not** apply
  to this build as-shipped. Downgrade/older-firmware route must be tested separately.

## Next steps

1. ~~Bind WinUSB~~ done. Fastboot drivable via libusb (prefer Linux).
2. Firmware acquisition: BBB100-3 Sprint autoloader/factory image → extract `aboot` + `abl`.
3. Determine if `aboot` is UEFI ABL; diff/analyze against CVE-2021-1931 pattern.
4. RE BIDE (`/dev/bide`, `libbidejni.so`) and `bbauthtoold`/TokenService — compare to
   Priv BIDE/Pathtrust audit; look for escalation primitives.
5. Examine `vtnvfsd` + `/nvram/nvuser` (write) for the `nvuser` token attack noted in BB10 repo.
6. Inspect `/proc/kallsyms` symbol list for the security stack + loadable module surface.
7. Reconstruct kernel config (no `/proc/config.gz`) from the published kernel branch
   `msm8953/ABY299` later; note this device is likely `msm8953/ABL766`-era. Check branch list.
