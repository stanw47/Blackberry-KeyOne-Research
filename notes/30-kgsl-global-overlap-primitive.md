# KEYone - kgsl global-region-overlap primitive (CVE-2020-11261)

Date: 2026-10-05
Related: notes/26, 29; docs/KEYone-kgsl-IOMMU-vulnerability.md.

## Result
tools/kgsl_global_overlap_poc.c maps 32 MB at CPU 0xf7000000 (spanning the GPU
global region 0xf8000000..0xf8800000) and calls MAP_USER_MEM with
hostptr=0xf7000000, len=0x2000000, memtype=ADDR, flags=USE_CPU_MAP.

Observed:
    [*] open = 3
    [*] mmap(FIXED 0xf7000000, 32MB) = 0x00000000f7000000
    <device dropped off USB; kernel panic/reboot>

pstore console-ramoops confirms a panic (clock_panic_callback,
cpr3_panic_callback, "Rebooting in 5 seconds"). Device rebooted cleanly;
serial/data intact.

## Why this matters
This is the actual CVE-2020-11261 primitive (GHSL-2020-374): the check only
validates start and end against the 8 MB global region. A range whose endpoints
are both outside but which SPANS it passes:
- gpuaddr      = 0xf7000000 -> not in [0xf8000000,0xf8800000)
- gpuaddr+size = 0xf9000000 -> not in [0xf8000000,0xf8800000)
- range [0xf7000000,0xf9000000) CONTAINS the whole global region.
The subsequent kgsl_mmu_map() installs GPU PTEs over the global region (which
holds setstate etc. mapped into every pagetable) -> corrupts GPU state -> panic.

Uses a moderate 32 MB size, avoiding the huge-allocation path (memdesc_sg_virt ->
vmalloc) that panicked the CVE-2023-33107 wraparound route (notes/29). Better,
cleaner primitive: reachable, modest size, demonstrably corrupts the global region.

## Two live-confirmed manifestations of the same bug
1. Missing SVM-range check (safe, T2): out-of-SVM address accepted.
2. Global-region overlap (this PoC): spanning range accepted -> global PTEs
   overwritten -> panic (corruption).

GHSL states this class "can be exploited to gain kernel code execution from a
userspace application similar to CVE-2023-33107". Turning the global-region
corruption into kernel R/W is the remaining step, then post-R/W under grsec.

## Safety
Both PoCs only map memory the process owns; the global-overlap variant corrupts
GPU state and panics by design of the bug. Device recovers on reboot. Do not run
on a device you need stable.

## Artifacts
- tools/kgsl_global_overlap_poc.c, tools/kgsl_bugA_poc.c (T1/T2/T4 safe; T3 off),
  tools/kgsl_gpuobj_poc.c, docs/KEYone-kgsl-IOMMU-vulnerability.md.
