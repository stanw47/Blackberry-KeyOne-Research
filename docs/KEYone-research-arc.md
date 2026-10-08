# BlackBerry KEYone: The Complete Software-Exploit Research Arc

*What we learned mapping every attack surface of a permanently-locked Android
phone — and the one real hole we found.*

---

## Introduction

The BlackBerry KEYone (BBB100-3) is a retail Android phone with a permanently
locked, server-authenticated bootloader and a grsecurity/PaX-hardened kernel.
For years the conventional wisdom has been that no software-only unlock or root
exists for it — unlike the KEY2, which fell to CVE-2021-1931 because it uses a
different (UEFI ABL) bootloader.

This article summarises a full software-exploit research effort on the KEYone:
what enforces its boot chain, every interface reachable from an unprivileged
context, which avenues are dead, and the one genuine kernel vulnerability that
remains reachable years after its upstream fixes.

## 1. What actually enforces the boot chain

The KEYone's root of trust is silicon, not software:

- The **Primary Boot Loader (PBL)** lives in mask ROM — etched into the SoC and
  impossible to modify. It verifies SBL1 against a hash of the root public key
  stored in one-time-programmable QFPROM eFuses.
- SBL1 verifies `aboot` (Little Kernel); `aboot` verifies the boot and recovery
  images. The device reports `flash.locked=1`,
  `ro.boot.binfo.bbss_wp_type=permanent`, and `bbss_insecure=false`.
- BlackBerry adds an `authboot`/RTAS2 layer on top of fastboot: privileged
  operations (unlocking, token provisioning, protected reads) require a signed,
  server-issued authorization. Those servers are long dead.

**Consequence:** you cannot *boot* a different bootchain, and a patched `aboot`
is rejected by SBL1's verification (observed on the Priv eMMC incident, where a
patched `aboot` bricked the device until recovered; not directly tested on the
KEYone). One nuance: the `flash` write path is **per-partition**, not globally
authboot-gated — boot/recovery/bootchain partitions accept arbitrary bytes
pre-auth (verified by writing a modified `boot.img` and reading it back through
the pre-auth SHA-224 oracle; see notes/49). Writes are still useless without a
valid signature, because every candidate image is ECDSA-verified at boot with
keys held by BlackBerry. The eMMC chip-off route that unlocked the Passport/Priv works only
because those devices have prototype bootloaders and a leaked `imggen` toolchain;
no equivalent exists publicly for the KEYone.

## 2. Every reachable surface

An exhaustive inventory of the board and its interfaces found that the
application processor is well defended but the peripherals are not all equally
hardened:

- **Bootloader / RTAS2**: hardened, and the authorization path is unreachable
  (dead servers). `securewipe` is un-gated but takes no input — not injectable.
- **WLAN (WCN36xx/prima)**: the classic SSID/length CVEs are already fixed in
  BlackBerry's build.
- **Diag / QMI / TrustZone**: SELinux- and group-gated; not reachable from
  `shell`.
- **Binder / ashmem**: the classic use-after-free classes are neutralised by
  grsecurity's slab isolation.
- **Adreno GPU (KGSL)**: `/dev/kgsl-3d0` is world-writable (`0666`) and the
  driver contains an unpatched range-validation bug.

## 3. The one real hole: KGSL IOMMU range validation

`kgsl_iommu_set_svm_region()` in the Adreno KGSL driver validates only the
endpoints of a requested GPU address range against the 8 MB "global" region. It
does not validate the range's interior, does not check the KGSL SVM range, and
has no wraparound guard. These are **CVE-2020-11261** (exploited in the wild,
CISA KEV) and **CVE-2023-33107**.

We confirmed the vulnerable code verbatim in BlackBerry's own published GPL
kernel source (branch `msm8953/ABY299`), and reproduced it live on a retail
KEYone from an unprivileged `shell`:

- **Missing SVM-range check (safe PoC):** an out-of-SVM address (e.g.
  `0x1dcc138000`) is accepted where a patched kernel returns `-ENOMEM`.
- **Global-region overlap (corruption / DoS):** a 32 MB range whose endpoints
  are both outside the global region, but which spans it, is accepted; the map
  overwrites the GPU's global page-table entries and panics the kernel.

The bug is not blocked by grsecurity, because the primitive is IOMMU
page-table aliasing rather than slab reuse.

## 4. Why it is a denial of service and not yet root

Turning the overlap into memory corruption requires overwriting an existing
page-table entry. The shipped kernel's io-pgtable code guards that with
`BUG_ON(!suppress_map_failures)` in `arm_lpae_init_pte()`, which panics instead
of corrupting. The io-pgtable selftest is not compiled in, so the flag is always
false and the guard is effectively unconditional. This is the same guard that
blocks the public CVE-2023-33107 exploitation chain.

So on this specific firmware the demonstrated impact is a reliable, unprivileged
**local denial of service**, and privilege escalation would require a novel
bypass of that guard.

## 5. What this means

- The KEYone's bootloader and trust architecture are sound; no software unlock
  was found, consistent with the device's reputation.
- Nonetheless, a **reachable, unpatched kernel vulnerability** exists in the GPU
  driver, with a reproducible unprivileged DoS and a corruption primitive that
  is one guard away from a full escalation.
- The research is fully documented and reproducible; the tools, proof-of-concepts,
  and write-ups are public.

## References

- CVE-2020-11261 / GHSL-2020-374 — GitHub Security Lab
- CVE-2023-33107 — Project Zero 0-day root-cause analysis
- BlackBerry GPL kernel source — `github.com/blackberry/android-linux-kernel`
- Detailed technical write-ups and PoCs: the research repository
