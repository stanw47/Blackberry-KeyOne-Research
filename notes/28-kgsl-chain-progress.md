# KEYone — kgsl chain progress (grooming primitives)

Date: 2026-10-05
Related: notes/26, 27; docs/KEYone-kgsl-IOMMU-vulnerability.md.

## What now works (safe, verified live)

tools/kgsl_gpuobj_poc.c (aarch64, zig) run from adb shell:

    [*] open = 3
    [*] GPUMEM_ALLOC_ID ret=0 id=1 gpuaddr=0x300000 mmapsize=0x1000 flags=0xc0000
    [*] mmap(offset=gpuaddr) = 0x265b61b000
    [*] wrote mapping OK, readback=0x41
    [*] GPUMEM_FREE_ID ret=0
    [*] done (safe)

=> We can allocate GPU buffers, mmap them (with the gpuaddr as the mmap offset),
read/write through the mapping, and free them. These are the primitives required
to groom the IOMMU rbtree (notes/26 step 1).

## Notes learned
- IOCTL_KGSL_GPUMEM_ALLOC_ID (0xC0300934) returns a kernel-assigned gpuaddr;
  mmap must use offset = gpuaddr (get_mmap_entry looks the entry up by
  pgoff<<PAGE_SHIFT).
- IOCTL_KGSL_GPUOBJ_ALLOC (0xC0300945) + mmap(offset=0) fails with -EINVAL
  because get_mmap_entry(pgoff=0) finds no entry.
- Default (non-CPU-map) allocations land at gpuaddr=0x300000
  (KGSL_IOMMU_SVM_BASE32), i.e. the 32-bit compat SVM range. 64-bit SVM
  (0x700000000) allocations need CPU-map flags / 64-bit hint.

## Remaining chain work
1. Determine whether the shipped ABL766 arm_lpae_init_pte carries
   BUG_ON(!suppress_map_failures) (ABY299 source does). Static kallsyms parsing
   of kernel.bin was inconclusive; options: dynamic test (panic = guard present,
   recoverable) or an alternative use of the rbtree corruption.
2. Build the grooming + race harness:
   - allocate UAF/OVERLAP/PLACEHOLDER objects in the 64-bit SVM range,
   - mmap them (creates rbtree entries + PTEs),
   - race MAP_USER_MEM with the wraparound BOGUS range,
   - mmap OVERLAP and detect the resulting corruption.
3. GPU command submission on 3.18 KGSL (for the dangling-PTE read/write stage).
4. Post-R/W privilege handling under grsecurity/PaX + SELinux.

Each step is testable on the device and recoverable.
