# BlackBerry KEYone & KEY2 Research

Reverse-engineering and modding research for the **BlackBerry KEYone (BBB100-3, Sprint)**
and **KEY2 (BBF100-6, India)** — bootloader analysis, security-stack mapping, LineageOS
installation, and firmware/lock research.

> **Disclaimer.** This repo is a *research aid*, not a flashing guide. Everything here is
> for educational / defensive research on devices owned by the author. Unlocking bootloaders,
> modifying eMMC boot partitions, and flashing firmware can **permanently brick** a device
> with no recovery short of JTAG/ISP chip-out. Proceed at your own risk. Large firmware
> blobs are **not** redistributed here — see each tool's source.

---

## Devices

| Device | Model | SoC | Bootloader | OS | Status |
|---|---|---|---|---|---|
| KEYone | BBB100-3 (Sprint/CDMA) | MSM8953 / SD625 | LK (`emmc_appsboot.mbn`) | 7.1.1 (ABL766) | Locked; research ongoing |
| KEY2 | BBF100-6 (India, dual-SIM) | SDM660 | UEFI ABL (`abl.elf`) | → LineageOS 22.2 | **Unlocked + running LineageOS** |

### The key architectural insight

```
Legacy lane (LK + bbss WP):   Priv  ──  KEYone     ← this repo's turf
Modern lane (UEFI ABL):       KEY2  ──  KEY2 LE    ← CVE-2021-1931 / kibo
```

Despite both "Key" devices being TCL-made, the **KEYone is architecturally closer to the
Priv** (legacy Qualcomm LK bootloader + BlackBerry `bbss` permanent boot-partition write
protect). The KEY2 jumped to a UEFI ABL stack — which is exactly why the CVE-2021-1931
fastboot exploit works on the KEY2 but **not** the KEYone.

---

## Key findings

### Security stack (KEYone, verified live)
- `ro.boot.binfo.bbss_wp_type = permanent` — **eMMC boot-partition write protect is permanent**
  (same `bbss` design as BB10 Passport/Priv; `B_PERM_WP_EN`, EXT_CSD[173]).
- `bbss_insecure = false`; `veritymode = enforcing`; `flash.locked = 1`.
- **BIDE** LSM (char device `/dev/bide`, 229:0), **Pathtrust**, **grsecurity/PaX** all present.
- BlackBerry trusted-computing libs: `libsecureservice.so` (RPMB/BSIS/BIDE over QSEE),
  `libbidejni.so`, `libbb_tokenservice.so`, `libbbauthtool.so`, `libbbusb.so`, `libbbry_vs.so`.
- `/nvram` fuse FS: `nvuser`, `perm`, `boardid`, `prdid`, `blog` via `vtnvfsd`.

### Bootloader (KEYone LK)
- `emmc_appsboot.mbn` — Qualcomm MBN-wrapped **ELF32 ARM LittleKernel**, loads at `0x8F600000`.
- Contains the full LK verification stack: `image_verify` (0x1d5372), `boot_linux_from_mmc`,
  `verify_hlos_image`, `fuse_verify`, plus BlackBerry `bbauthtool`/`rtas`/`nvverify` additions.
- `"Device is unlocked! Skipping verification..."` and
  `"Insecure bootchain detected. Skipping fuse verification check"` — the LK analogues of
  `bbss.insecure`.
- Relevant CVEs to test: **CVE-2013-2598**, **CVE-2014-0973** (LK sig-verification bypass).

### EDL / firehose
- Software EDL entry (`adb reboot edl`) is **disabled** on production units (verified empirically).
- PBL-ROM EDL (test points) still exists (`boot_dload.c` present in SBL1).
- A **BlackBerry-signed firehose programmer** (`prog_emmc_firehose_8953_ddr.mbn`) — a
  **DEV/test loader** with `peek`/`poke` and BBRY digest placeholders — was extracted from the
  official autoloader. Promising no-desolder lever.

### KEYone — unprivileged kernel vulnerability (KGSL/IOMMU) — CONFIRMED LIVE
- **CVE-2020-11261 / CVE-2023-33107** class: `kgsl_iommu_set_svm_region()` has **no
  SVM-range validation** (only the 8 MB global-region start/end check). The 2021/2023
  fixes (`iommu_addr_in_svm_ranges()`) are **absent** from BlackBerry's own published
  msm8953 kernel source (`msm8953/ABY299`), and the tested ABL766 kernel is from 2018.
- **Reachable from unprivileged `shell`**: `/dev/kgsl-3d0` is `0666`
  (`u:object_r:gpu_device:s0`), opens with no SELinux denial, ioctls execute.
- **Live proof**: `tools/kgsl_bugA_poc.c` gets `IOCTL_KGSL_MAP_USER_MEM` to accept a
  valid user page **outside** the SVM range (e.g. `0x92f800000`) — a patched kernel
  returns `-ENOMEM`. Reproduced twice; device healthy. Also a trivial local DoS
  (oversized length → kernel panic).
- Not blocked by the grsecurity slab isolation that neutralises Binder/ashmem UAFs
  (the primitive is IOMMU page-table aliasing).
- Full writeup with reproducible steps and evidence:
  [`docs/KEYone-kgsl-IOMMU-vulnerability.md`](docs/KEYone-kgsl-IOMMU-vulnerability.md).

### KEY2 → LineageOS
- Full install verified: **LineageOS 22.2 (Android 15)**, kernel 4.4.302, dual-SIM working.
- Unlock via CVE-2021-1931 (`BlackBerryBootUnlock.exe` / kibo), ACQ160 base flashed twice.
- See [`docs/KEY2-LineageOS-Guide.md`](docs/KEY2-LineageOS-Guide.md).

### Oreo / "frankenstein" (KEYone)
- Server-side verification via `tcl-fw` against **TCL's own FOTA servers** confirms the
  **BBB100-3 never received an Oreo build** (latest = ABT855, 7.1.1).
- Cross-variant flashing is blocked by the signed boot chain + permanent boot-WP; and even
  ignoring that, modem/RIL/`fsg`/`modemst` mismatch would break the radio and IMEI.

---

## Repository layout

- `notes/` — session research notes (device recon, security stack, LK analysis, TCL FOTA verification)
- `docs/` — write-ups, including the KEY2 LineageOS guide
- `tools/` — analysis helpers: `lk_analyze.py`, `elf_triage.py`, `fastboot_libusb.py`, `fb_probe.py`
- `recon/` — raw recon captures (props, partitions, kallsyms, SELinux policy) and pulled security libs
- `firmware/` — **not committed** (large blobs); extraction instructions in notes
- `abl/`, `edl/`, `exploit/`, `kernel/` — work areas

---

## Tools

| Tool | Purpose |
|---|---|
| `tools/lk_analyze.py` | LK (emmc_appsboot.mbn) MBN/ELF string + reference analyzer |
| `tools/elf_triage.py` | LIEF/capstone ELF triage (exports + interesting strings) |
| `tools/fastboot_libusb.py` | Drive BlackBerry fastboot (`0FCA:8040`) directly over libusb |
| `tools/fb_probe.py` | Robust fastboot-over-libusb probe |

External tooling referenced: `botchedRPR/kibo`, `vehoelite/tcl-fota-tool`, `bkerler/edl`,
`FumoEnterprises` (KEY2 LineageOS device trees), `balika011` (Passport/Priv conversion).

---

## References

- **CVE-2021-1931** — Qualcomm fastboot/ABL buffer overflow (KEY2/KEY2LE unlock) — Christopher Wade / Pen Test Partners
- **CVE-2013-2598 / CVE-2014-0973** — LK bootloader signature-verification bypasses
- **kibo** — https://github.com/BotchedRPR/kibo
- **tcl-fw** — https://github.com/vehoelite/tcl-fota-tool
- **KEY2 LineageOS** — https://github.com/Borgified/Lineage-BBKey2 (community) / XDA threads
- **BB10 root/RAM-loader research** — https://bb10.root.sx

---

## License

Research notes and original scripts are provided for educational purposes. Third-party code
retains its own license.
