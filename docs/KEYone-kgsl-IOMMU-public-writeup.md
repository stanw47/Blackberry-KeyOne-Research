# BlackBerry KEYone: A Reachable, Unpatched Kernel Vulnerability in the Adreno GPU Driver

*A local, unprivileged denial-of-service and corruption primitive in the KGSL IOMMU
handler (CVE-2020-11261 / CVE-2023-33107 class) on the BlackBerry KEYone (BBB100-3).*

---

## Summary

The BlackBerry KEYone ships a Qualcomm Adreno KGSL driver with a missing
range-validation bug in its GPU shared-virtual-memory (SVM) region handler,
`kgsl_iommu_set_svm_region()`. The device node `/dev/kgsl-3d0` is world-writable
and reachable from an unprivileged `shell` context; the kernel predates the
upstream fixes by years; and the bug is not blocked by the grsecurity hardening
that protects the rest of the kernel.

We confirmed the vulnerable code in BlackBerry's own published GPL kernel source,
and reproduced it live on a retail KEYone with reproducible proof-of-concepts:
one safe PoC that demonstrates the missing check, and one that corrupts GPU state
and panics the kernel (an unprivileged local denial of service). Turning the bug
into privilege escalation is blocked on this firmware by an io-pgtable guard that
converts the would-be memory corruption into a crash.

## Background

The KEYone is a retail BlackBerry Android phone with a permanently locked,
server-authenticated bootloader (`authboot`/RTAS2) and a grsecurity/PaX-hardened
kernel. Prior work established that the bootloader, token, and TrustZone paths are
gated, and that the classic kernel use-after-free classes (Binder, ashmem) are
neutralised by grsecurity's slab isolation. The Adreno/KGSL IOMMU bug is the
first reachable crack in that software-only defense.

## The vulnerability

`kgsl_iommu_set_svm_region()` validates only the **start and end** of a requested
GPU address range against the GPU's small "global" region. It never validates:

- the **interior** of the range (a range can span the global region while both
  endpoints lie outside it), and
- that the range lies within the KGSL SVM range (the 2021 fix added
  `iommu_addr_in_svm_ranges()`),
- and it has no wraparound guard (the 2023 fix added one).

Neither fix exists in BlackBerry's published msm8953 kernel source (branch
`msm8953/ABY299`), and the tested device's kernel was built in November 2018.

## Reachability

- `/dev/kgsl-3d0` is `crw-rw-rw-` (`u:object_r:gpu_device:s0`), opens from
  `shell` with no SELinux denial, and the relevant ioctls execute.
- The bug is reached through the ordinary `IOCTL_KGSL_MAP_USER_MEM` ioctl
  (`memtype = KGSL_USER_MEM_TYPE_ADDR`, `flags = KGSL_MEMFLAGS_USE_CPU_MAP`).
- The primitive is IOMMU page-table aliasing, not slab reuse, so grsecurity's
  slab isolation does not apply.

## Proof-of-concept results

**Missing SVM-range check (safe).** `IOCTL_KGSL_MAP_USER_MEM` accepts a valid user
page whose address lies outside the KGSL SVM range (e.g. `0x1dcc138000`). A
patched kernel returns `-ENOMEM`; the KEYone returns `0`.

```
[*] T1 in-SVM-range      hostptr=0x700000000  len=0x1000 -> 0
[*] T2 out-of-SVM-range  hostptr=0x1dcc138000 len=0x1000 -> 0   <== MISSING SVM RANGE CHECK
```

**Global-region overlap (corruption / DoS).** A 32 MB range
`[0xf7000000, 0xf9000000)` whose endpoints are both outside the 8 MB global
region `[0xf8000000, 0xf8800000)` — but which spans it — is accepted. The
subsequent map installs GPU page-table entries over the global region (which
holds GPU scratch state used by every pagetable), corrupting it and panicking the
kernel:

```
[*] open = 3
[*] mmap(FIXED 0xf7000000, 32MB) = 0x00000000f7000000
<device drops off USB; kernel panic/reboot>
```

The device reboots cleanly; no data loss was observed. Both PoCs map only memory
the calling process owns.

## Impact

- **Unprivileged local denial of service** — reliable kernel panic from
  `adb shell` (uid 2000, SELinux enforcing).
- **Not blocked by grsecurity.**
- **Privilege escalation is blocked on this firmware** by the shipped kernel's
  io-pgtable guard (`BUG_ON(!suppress_map_failures)` in `arm_lpae_init_pte`),
  which turns the would-be PTE corruption into a panic — the same guard that
  blocks the public CVE-2023-33107 chain. A full root would require a novel
  bypass of that guard.

## Reproduce

All tools and a step-by-step guide are in the research repository:
`docs/KEYone-kgsl-IOMMU-vulnerability.md`. The PoCs are freestanding aarch64
binaries built with a cross-compiler and pushed to `/data/local/tmp`:

```
zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding \
    -fno-builtin -O2 -Wl,-e,_start -o kgsl_bugA_poc kgsl_bugA_poc.c
adb push kgsl_bugA_poc /data/local/tmp/
adb shell chmod 755 /data/local/tmp/kgsl_bugA_poc
adb shell /data/local/tmp/kgsl_bugA_poc
```

> Warning: the global-overlap PoC corrupts GPU state and panics the kernel by
> design of the bug. Run only on a device you can reboot.

## Disclosure

The underlying defects are already public: **CVE-2020-11261** (Qualcomm
January-2021 bulletin; CISA Known Exploited Vulnerabilities) and
**CVE-2023-33107** (Qualcomm October-2023 bulletin; Project Zero 0-day RCA). This
work contributes the device-specific confirmation that the KEYone (BBB100-3,
ABL766, kernel 3.18.31) remains vulnerable years after the fixes, with a safe,
reproducible, unprivileged proof-of-concept. BlackBerry has exited the handset
business and the device is end-of-life.

## References

- GHSL-2020-374 / CVE-2020-11261 — GitHub Security Lab, "Kernel code execution in Qualcomm kgsl driver"
- CVE-2023-33107 — Project Zero, "Qualcomm Adreno GPU KGSL_IOCTL_GPUOBJ_IMPORT integer overflow"
- BlackBerry GPL kernel source — `github.com/blackberry/android-linux-kernel`, branch `msm8953/ABY299`
- Android Security Bulletin, January 2021
