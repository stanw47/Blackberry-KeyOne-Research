# KEYone — kgsl Bug A CONFIRMED LIVE (safe PoC)

Date: 2026-10-05
Related: notes/24, 25, 26.
Status: LIVE-CONFIRMED, REPRODUCIBLE, SAFE.

## Result

tools/kgsl_bugA_poc.c (aarch64 static, zig) run twice from adb shell
(uid 2000, SELinux enforcing), device healthy both times:

    [*] open /dev/kgsl-3d0 = 3
    [*] mmap(FIXED 0x700000000) = 0x700000000
    [*] T1 in-SVM-range  hostptr=0x700000000 len=0x1000 -> 0
    [*] mmap(anon) = 0x92f800000                     (outside SVM range)
    [*] T2 out-of-SVM-range hostptr=0x92f800000 len=0x1000 -> 0   <== MISSING SVM RANGE CHECK
    [*] done (no overlap/PTE path used; safe)

## Why this is conclusive

kgsl_iommu_set_svm_region() on the vulnerable kernel only checks the 8 MB
global region [0xf8000000,0xf8800000). It has NO check that the requested range
lies in the KGSL SVM range (0x700000000..0x800000000 for 64-bit).

- T1 maps a page at 0x700000000 (inside SVM) -> success (expected on any build).
- T2 maps a page at 0x92f800000 / 0x41d8bc8000 (a normal anonymous mmap address,
  far outside the SVM range) -> success.
- On a patched kernel, the 2021 fix's iommu_addr_in_svm_ranges() returns false
  for T2 (neither compat 0x300000..0xBFF00000 nor svm 0x700000000..0x800000000
  contains it) -> -ENOMEM.

Therefore T2 succeeding is direct, unprivileged, live proof that
CVE-2020-11261 / CVE-2023-33107 is present and reachable on the KEYone.

The PoC is safe: it only maps a page the process owns, uses no wraparound, no
overlap, no PTE path, and frees the mapping via IOCTL_KGSL_SHAREDMEM_FREE.

## Bonus finding: huge-size DoS

The first PoC version also ran T3: len = 0xfffffffffffff000 (wraps to 0).
This panicked the kernel (device dropped off adb, rebooted cleanly; serial
intact). So the same missing check also yields a trivial local DoS via
memdesc_sg_virt/kvcalloc overflow on an enormous size. T3 is disabled in the
committed PoC.

## What remains for a full root chain
- The RCA's PTE-deletion step depends on arm_lpae_map_sg's unchecked
  arm_lpae_init_pte — present, but arm_lpae_init_pte carries
  BUG_ON(!suppress_map_failures) in the ABY299 source (would panic rather than
  silently corrupt). Must be checked against the shipped ABL766 binary, or
  bypassed via another use of the rbtree corruption.
- Remaining work: rbtree grooming + race reliability + GPU command submission on
  3.18 KGSL + post-R/W cred handling under grsec. Substantial.

## Artifacts
- tools/kgsl_bugA_poc.c (T3 disabled) — safe live PoC.
- tools/kgsl_probe.c, tools/kgsl_abi_probe.c.
- Live evidence: two runs above.
