# BlackBerry KEYone (BBB100 "Mercury") — Research Compendium

Compiled 2026-10-02. Sources: XDA, CrackBerry, Reddit r/blackberry, GitHub
(zenfyrdev/bootloader-unlock-wall-of-shame, BotchedRPR/kibo, Giovix92/EDLUnlock,
alephsecurity), NVD, GSMArena, Wikipedia, archive.org, AndroidFileHost, HalabTech.

---

## 1. Device & lineup

- **Marketing name:** BlackBerry KEYone (stylized KEYone); dev codename **Mercury**.
- **Maker:** TCL Communication under BlackBerry Mobile license. Released 2017-04.
- **Successor:** KEY2 (BBF100, "Athena") / KEY2 LE (BBE100, "Luna").
- **SoC:** Qualcomm **MSM8953** = Snapdragon **625** (14nm, 8x Cortex-A53
  2.0 GHz), Adreno 506, **arm64-v8a**.
- **OS:** shipped Android 7.1.1 Nougat; later 8.1 Oreo for most variants.
- **Boot chain:** Qualcomm PBL → XBL/SBL → **ABL** (`aboot`/UEFI, hosts
  fastboot) → boot.img.
- **Storage:** eMMC 5.1 (32/64 GB); NTFS/exFAT SD.

### Variants / models

| Model | Regions | Notes |
|---|---|---|
| BBB100-1 | USA/Canada/LATAM/APAC | "US v1", original unlocked |
| BBB100-2 | EMEA (Europe/ME/Africa) | most common globally |
| BBB100-3 | **USA v2 (Sprint)** | **← our device**; CDMA |
| BBB100-4 | India | dual-SIM, "Limited Edition" (4 GB/64 GB) |
| BBB100-5 | (Black/Bronze ed.) | unlocked |
| BBB100-6 | Japan | limited edition black |
| BBB100-7 | China (TCL) | |

- PRD numbers encode carrier variant (e.g. BBB100-1: PRD-63116-001 unlocked,
  -003 Bell, -005 Rogers, -036 AT&T). Same hardware per model; firmware **only
  compatible within the same model**.
- **Carrier update dynamics:** TCL/BlackBerry released monthly patches; carriers
  lagged. Sprint (BBB100-3) **never got Oreo** — CDMA variants stayed on 7.1.1.
- **OTA variant-switching:** Markus Birth's `tcl_ota_check` / matrix allowed
  pulling a newer patch from another PRD of the same model. The "Updates
  advanced mode" entry was disabled by TCL in Oct-2017 firmware, then the Janus
  bug allowed a downgrade of the updater, then closed by Dec-2017.

### Our unit (live read 2026-10-02)

| Field | Value |
|---|---|
| Model | **BBB100-3** |
| product | `bbb100usasprint`, device `bbb100` |
| Build | `NMF26F` / display **`ABL766`** (Dec-2018 patch) |
| Security patch | 2018-12-05 |
| Bootloader | **locked** (`ro.boot.flash.locked=1`) |
| OEM unlock | `ro.oem_unlock_supported=0`, `sys.oem_unlock_allowed=0` |
| verity | `ro.boot.veritymode=enforcing`; dm-verity active |
| crypto | `ro.crypto.state=encrypted` (block/FBE) |
| SELinux | **Enforcing** |
| Root | none (`id` = uid 2000 shell; no `su`) |
| Partitions | `persist`, `bbpersist`, `modem`, `oempersist` visible in mounts |
| Mounts | `/system` = `dm-0` ext4 ro; `/persist`,`/bbpersist`,`/oempersist` rw |

---

## 2. The bootloader story (the crux)

TCL/BlackBerry use a **modified fastboot called `authboot`** that demands
**authorization from a TCL/BlackBerry server** for any bootloader-related
operation. Without it you cannot unlock or flash unsigned images.

Known from community reverse-engineering (DiabloSat et al.):
- `fastboot flash ...` on a retail KEYone → `FAILED (remote: 'authboot command
  permission denied')`.
- Hidden OEM commands exist (`oem unlock-go`, `oem unlock`, `oem lock`,
  `oem device-info`, `oem set-factory-mode`, `oem set-product-mode`,
  `preflash`, `oem format`, `oem gptinfo`, ...) but are gated by authboot; the
  bootloader is always in "product mode".
- `oem set-factory-mode`/`set-product-mode` would enable a lot, but permission
  denied. `/system/bin/mfgUtil` only runs in factory mode.
- `fastboot oem device-info` traditionally reports unlock/tamper/verified flags.

### Two important historical facts
1. **"The KEYone was unlockable before it got a patch."** Early firmware
   permitted OEM unlock; a later ABL update closed it. Early-batch or
   engineering units behave differently.
2. **TWRP 3.2.1 port (SKDushow, 2021)** and a "TWRP for KEYone (None bootloader
   version)" exist, but only work on **factory-unlocked / engineering prototype**
   KEYones (green LED/dev units) — retail locked units get authboot-denied.
   `fastboot boot <img>` also returns `unknown command` on these units.

### Key2 breakthrough (does NOT yet include KEYone)
- **CVE-2021-1931** = a Qualcomm ABL/fastboot bug that BlackBerry/TCL never
  patched on the **KEY2 (SDM660)**. Used via the **`kibo`** tool (BotchedRPR) to
  get a fully untethered **permanent** bootloader unlock.
- Quirks: device must have no Google account/password; flash the correct
  firmware **twice** (BlackBerry botched A/B); after unlock you need a
  **modified boot image** to boot stock OS because of FACTORY_MODE restrictions.
- Result: **LineageOS 22.2 (Android 15)** and /e/OS now run on KEY2/KEY2LE
  (krab-ubica, BotchedRPR, npjohnson blobs from Nokia SDM660).
- **KEYone status:** explicitly *"KeyOne should be made too, but it's not done"*.
  kibo is **SDM660-specific** ("BlackBerry SDM660 Bootloader tools"). KEYone is
  MSM8953 with a 2016-era ABL; CVE-2021-1931 applicability unconfirmed.

---

## 3. EDL (9008) route

- Every MSM SoC has **EDL** in the PBL; device enumerates as `Qualcomm HS-USB
  QDLoader 9008` (USB `05c6:9008`). Entered via test points (short to GND on
  boot), an "EDL/deep-flash" USB cable, or sometimes `adb reboot edl` /
  `fastboot oem edl`.
- **The blocker is the signed firehose programmer**, matching the OEM RSA keys
  fused into the SoC. For BlackBerry no public programmer is known (same
  situation as Nokia/MS Lumia). Community effort tracked in
  `SaintPepsi/claude-on-blackberry` (Priv, MSM8992) — still open.
- **Aleph Research** (`alephsecurity.com/2018/01/22/qualcomm-edl-*`) showed the
  leaked-Xiaomi-programmer attack chain, incl. **MSM8953** PBL reverse
  engineering and a **devinfo-partition bootloader-unlock** storage attack.
- **`Giovix92/EDLUnlock`** unlocks via EDL by patching the **`devinfo`**
  partition unlock bytes — but **requires a working (patched) firehose `.mbn`**;
  repo ships an MSM8953 (Mi A1/tissot) `prog_emmc_firehose_8953_ddr.mbn`.
  *If* a BlackBerry/MSM8953-compatible signed programmer could be sourced, the
  same devinfo patch could unlock a KEYone. None public yet.
- MSM8953 firehose files circulate for Xiaomi (`prog_emmc_firehose_8953_ddr.mbn`)
  but PBL signature verification means a non-BlackBerry programmer won't load
  unless the MSM8953 PBL sig-check bug applies (2016 chips: debated/patch-
  dependent).

---

## 4. What people HAVE done with a KEYone

**Without root / locked bootloader (works today):**
- **Debloat via ADB** — large community lists (`pm uninstall --user 0 ...`);
  restore with `pm install-existing`.
- **FRP (Google-lock) bypass** — several 2025–2026 guides (Chrome → bypass site
  → install launcher APK route); patch-dependent.
- **Backup user data** via `adb backup`; no system partition access.
- **OTA / variant firmware switching** (same model) via `tcl_ota_check`.
- **Autoloader flashing** — full signed factory images + `flashall` scripts
  (BlackBerry's own). Used for **unbrick / restore / FRP reset**. Community
  mirrors only (BlackBerry's portal closed 2022):
  - AndroidFileHost (Jcrutchvt10 "Keyone Autoloaders", 2017–2018 builds)
  - HalabTech (`bbry_qc8953_autoloader_user-all-*`, `RomKEYoneSprint...`)
  - archive.org (`black-berry-key-one` firmware+apps)
  - Autoloaders: `AAN358`, `AAN355`, `AAO472`, `AAM481`, `AAO548`, `AAP638`,
    `AAQ302`, `AAT166`, `AAV222`, `AAX863`, `AAS212`, `ABG366`, `ABT974`, ...
  - **No Ubuntu/Linux autoloader** historically (Windows `.exe`/`.bat`); some
    community `flashall.sh` derivatives exist.
- **Fastboot mode access** (Vol Dn + Power) for diagnostics; most write cmds
  authboot-denied.

**With an engineering / early unlocked KEYone:**
- Flash **TWRP 3.2.1** (SKDushow port; keyboard + touch working in his test).
- Potentially Magisk root (patch boot.img, flash) — *only* on unlocked units.
- No stable, maintained custom ROM for KEYone exists (contrast KEY2's LOS 22.2).

**Root reality:** On a **locked retail** KEYone there is **no public root**.
One-click tools (KingRoot/KingoRoot) do not work on Nougat KEYone and are widely
considered adware/malware (banned on XDA). No Magisk without unlocked bootloader.

---

## 5. Known vulnerabilities / research touching the platform

- **CVE-2014-2389** — qconnDoor stack buffer overflow on BB10 Z10 (context for
  the classic BB10 root ritual, not KEYone).
- **CVE-2021-1931** — Qualcomm ABL vulnerability → KEY2/KEY2LE permanent unlock
  (kibo). KEYone untested.
- **CVE-2022-38694** — Unisoc/Spreadtrum ABL unlock (TomKing062); not Qualcomm.
- **Qualcomm "Breaking Mobile Bootloaders" (QPSS'22, Christopher Wade)** —
  reverse-engineered a vendor-restricted `flash:` command on an SDM660 phone
  (4 days) to achieve bootloader unlock; baseline for the KEY2 approach.
- **MSM8953** alone has 355 CVEs tracked; 4 on CISA KEV. Many are kernel/SoC,
  not bootloader.
- **BIDE / Pathtrust** are BB10 (Classic/Passport) LSM protection mechanisms —
  *not* present on the Android KEYone. Different world from the BB10 work.

---

## 6. Realistic levers for our BBB100-3 (Sprint, ABL766, locked)

1. **Check unlock ability empirically** (needs a manual reboot to bootloader):
   `fastboot oem device-info`, `fastboot getvar all`,
   `fastboot flashing get_unlock_ability`, `fastboot oem unlock` /
   `fastboot oem unlock-go`. Expect `authboot` denial. (Read-only-ish; some
   commands may reset nothing. Do NOT `flash`.)
2. **EDL reconnaissance** (needs test points / teardown): confirm PBL falls to
   EDL, read `MSM_ID`/`PK_HASH` via Sahara (`bkerler/edl`, `qdl`), then hunt a
   BlackBerry-signed MSM8953 firehose programmer inside **autoloader packages**
   (`prog_emmc_firehose_*` / `*.elf`), repair-tool sets, or the device's own
   engineering partitions. This is the highest-value unknown.
3. **If a programmer is obtained** → dump/backup all partitions, then patch
   `devinfo` unlock bytes (EDLUnlock method) → unlocked bootloader → TWRP →
   Magisk → custom ROM. Also enables full forensic backup.
4. **Autoloader set as reference** — collect stock KEYone images for diffing
   (ABL/firmware) and as unbrick insurance before any experiment.
5. **Non-destructive meantime:** ADB debloat, full `adb backup`, document
   `getprop`, partition map, and any accessible MTP content.

### Open questions
- Is `ro.oem_unlock_supported=0` a hard fuse on BBB100-3, or a hidden toggle?
- Does the **Dec-2018 ABL766** still contain the early OEM-unlock path?
- Is there any BlackBerry MSM8953 **firehose programmer** anywhere (autoloaders,
  Cellebrite/MSAB/Oxygen, repair boxes)?
- Can the KEY2 CVE-2021-1931/kibo path be adapted to MSM8953 ABL?

---

## 7. Source index

- Variants/PRD: blog.mbirth.uk (KEYone OTA for different variants), GSMArena.
- Autoloaders: forums.crackberry.com `blackberry-keyone-autoloaders-1108372`;
  AndroidFileHost `?flid=204896`; support.halabtech.com `id=129132`;
  archive.org `details/black-berry-key-one`.
- Bootloader wall of shame: github.com/zenfyrdev/bootloader-unlock-wall-of-shame
  (`brands/tcl/README.md`).
- KEY2 unlock + kibo: xdaforums.com `unlock-bootloader-...key2-athena-key2-le-luna.4781022`;
  github.com/BotchedRPR/kibo; reddit r/blackberry `1l08n9u`.
- KEY2 LineageOS: xdaforums.com `rom-15-unofficial-beta-athena-lineageos-22-2...4777062`,
  `...luna...4777414`.
- EDL: alephsecurity.com/2018/01/22/qualcomm-edl-1/; github.com/Giovix92/EDLUnlock;
  github.com/bkerler/edl; github.com/andersson/qdl.
- CrackBerry hidden fastboot commands thread (ID 1114897).
- XDA "Force BlackBerry KeyOne into EDL Mode?" (4207481).
- Reddit FRP bypass guide (`1rq61uj`, 2026-03).
