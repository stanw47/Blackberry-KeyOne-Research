# KEYone — Boot-chain model, patch rationale, and the meta-threat-model

Date: 2026-10-05
Related: notes/19 (kernel survey), notes/20 (hardware), notes/21 (surface map),
notes/22 (CVE-2019-10526 patched).

## 1. What actually enforces the boot chain (silicon, not software)

Qualcomm secure boot (QTI "Secure Boot and Image Authentication"):
- **PBL (Primary Boot Loader) lives in mask ROM** — etched into the SoC,
  *"cannot be physically altered."* It is the first code that runs on every power-on.
- PBL verifies **SBL1** against a **SHA-256 hash of the Root CA public key stored in
  QFPROM eFuses** (one-time-programmable, irreversible).
- SBL1 verifies **aboot (LK)**; aboot verifies **boot/recovery**; TZ images are
  verified in parallel by the secure side (XBL_SEC/TME on newer, SBL1/TZ here).
- Fuse state on our device: secure boot ON, `flash.locked=1`,
  `ro.boot.binfo.bbss_wp_type=permanent`, `bbss_insecure=false`.

Consequence: **you cannot "flash a different bootchain."** Any image that doesn't
satisfy the fused key hash is rejected at load (SBL1), exactly as we observed when
a patched `aboot` bricked the device (Priv incident, and SBL1 re-verify is real).

### Why the Passport eMMC swap worked but KEYone's wouldn't
- Passport/Priv: fuses anchored to a **prototype/dev** key, and a **leaked prototype
  bootloader** image satisfies it. Chip-off just grants write access to boot0.
- KEYone: anchored to the **production** key; **no prototype KEYone bootloader
  exists publicly**, and **no `imggen`-equivalent** for MSM8953. A bare eMMC in a
  programmer would still have nothing valid to write.
- Therefore the ONLY viable classes are (a) a bug in a signed, running bootstage
  (LK `aboot`, which runs pre-TZ and is not grsec-hardened), or (b) a bug in the
  running OS kernel reaching TZ / bypassing grsec, or (c) hardware (off table).

## 2. Why the post-2018 patches exist (root causes)

| CVE | Component | Root cause (why patched) | Blocked for us by |
|-----|-----------|--------------------------|-------------------|
| CVE-2019-2215 | Binder | `binder_thread->wait` waitqueue freed on `BINDER_THREAD_EXIT` but not removed from epoll -> UAF on process exit. **Weaponized in-the-wild (NSO Pegasus)** -> CISA KEV. | grsec slab isolation + `CONFIG_DEBUG_LIST` + silent Dec-2017 upstream fix in 3.18 |
| CVE-2019-2025 | Binder | improper locking in `binder_thread_read` -> UAF | fixed upstream pre-snapshot; grsec slab |
| CVE-2020-0009 | ashmem | `ashmem_mmap` VMA prot mask undone by `remap_file_pages()`; `ASHMEM_UNPIN` unauthenticated -> RO bypass (Chrome/ART JIT) | RO-bypass/DoS class; no root primitive alone |
| CVE-2020-0041/0035 | Binder | transaction-queue OOB / refcount bugs | grsec slab |
| CVE-2019-10526 | WLAN (prima) | NULL not placed after SSID name -> OOB write | **fix verified present** (notes/22) |
| CVE-2019-14074 | Diag | heap overflow in diag cmd handler (attacker packet length) | `/dev/diag` EACCES to shell |
| CVE-2019-14114 | WLAN fw | GTK IE overflow | firmware-side/remote |
| CVE-2020-11116/17/18 | WLAN HOST | WMI event / array index | qcacld-3.0-era, not in prima 3.0.11.66 |
| CVE-2020-3611 | QTEE | TrustZone | gated |

**Meta-threat-model revealed by the patch set:**
- Vendors patched exactly the **app-reachable memory-corruption** surfaces:
  Binder, ashmem, WLAN netlink, diag, GPU.
- Every one is a **UAF / OOB / unauthenticated-ioctl** class.
- BlackBerry's **grsec + SELinux** build neutralizes the *primitive* (slab reuse,
  ptrace, TPE, device ACLs) for precisely those classes.
- The withheld-patch CVEs (e.g. 10526) signal a **clean reusable primitive** — worth
  targeting for the *pattern*, even when that instance is patched.

=> The patch list is a **map of what the vendors feared was reachable**. The
un-patched residue is where to hunt: surfaces with **no known bug**, or bugs whose
primitive grsec removed.

## 3. Productive interpretation
1. **Reachable-but-hardened** surfaces (WLAN host, Binder, ashmem) still warrant
   fuzzing because the *next* bug (post-2018, never patched here) may not need the
   grsec-blocked primitive (e.g. an OOB *write* primitive works without slab reuse).
2. **Reachable-and-not-grsec** surfaces are the best:
   - `/dev/kgsl-3d0` (0666) — GPU/SMMU/DMA; the one class that historically survives grsec.
   - **LK `aboot`** — runs pre-TZ, no grsec, historically buggy (KEY2 CVE-2021-1931
     was an ABL fastboot bug). KEYone's aboot is a *different* codebase and appears
     to have **never been publicly fuzzed**.
3. **The KEYone aboot is the standout untried target.**

## 4. Plan: aggressive automated sweep
See notes/24 (`tools/surface_sweep.py` + `tools/aboot_fuzz.py`): a unified harness
that enumerates every reachable syscall/ioctl/netlink/socket surface and fires
structured+mutated inputs at each, logging any abnormal response (crash, hang,
reboot, changed error) for triage. Target: find one hole.
