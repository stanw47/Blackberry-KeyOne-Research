# KEYone — kgsl chain progress: obstacles + analysis

Date: 2026-10-05
Related: notes/26, 27, 28; docs/KEYone-kgsl-IOMMU-vulnerability.md.

## Confirmed so far
- Bug A (missing SVM-range / wraparound validation in kgsl_iommu_set_svm_region)
  is present (BB source) and live-confirmed safely (T2; T4 wraparound reached).
- Grooming primitives work (GPUMEM_ALLOC_ID + mmap(offset=gpuaddr) + rw + free).
- Safe wraparound (T4, high hostptr + small size) inserts the BOGUS rbtree entry
  and fails gracefully in get_user_pages (-EFAULT). No panic. Repeatable.

## The obstacle for the RCA chain on this kernel
The Project Zero chain needs a BOGUS rbtree entry whose base sits mid-range
(between victim and placeholder) with a huge size that wraps the end:
BOGUS: 0x700204000 -> 0x700101000 (size 0xffffffffffefd000).

On this kernel that requires a huge size in MAP_USER_MEM:
- kgsl_setup_anon_useraddr() inserts the BOGUS entry (global check bypassed by
  the wrap), then always calls memdesc_sg_virt().
- memdesc_sg_virt(): sglen = size/PAGE_SIZE; rejects only sglen >= LONG_MAX.
  For a huge size sglen passes and it calls
  kgsl_malloc(sglen * sizeof(struct page *)).
- kgsl_malloc (kgsl.h) = kzalloc if <= PAGE_SIZE else vmalloc(size).
  A ~9 EB vmalloc should fail (size>>PAGE_SHIFT > totalram_pages -> NULL), but in
  practice the huge-length variant (T3) panicked/rebooted the device (cause not
  confirmed; pstore is SELinux-denied to shell).

Consequence: the mid-range-base BOGUS (needed to fool the overlap check) goes
through the huge-size path that misbehaves here. The alternative high-base +
small-size BOGUS (T4) avoids the panic but places the entry at the far right of
the rbtree, where it cannot misdirect the overlap search for a mid-range victim.

=> The documented CVE-2023-33107 technique does NOT transfer as-is to this 3.18
KGSL. A full exploit needs either:
  (a) a way to insert a mid-range BOGUS without the huge allocation (alternate
      entry path, or making memdesc_sg_virt fail earlier/gracefully),
  (b) a different use of the overlapping-rbtree corruption, or
  (c) acceptance of the confirmed DoS as the practical impact.

## Also open
- Whether shipped ABL766 arm_lpae_init_pte carries
  BUG_ON(!suppress_map_failures) (ABY299 source does). Needed only for the
  PTE-deletion step; moot until (a)/(b) is solved.

## What is solidly delivered
- docs/KEYone-kgsl-IOMMU-vulnerability.md - full writeup, reproducible, pushed.
- tools/kgsl_bugA_poc.c - safe live PoC (T1/T2/T4; T3 disabled).
- tools/kgsl_gpuobj_poc.c - grooming primitives.
- tools/kgsl_probe.c, tools/kgsl_abi_probe.c.
- notes/24-28.

## Next concrete options
1. Instrument the huge-size path to find the panic (pstore alternate paths, or
   vary size to find threshold) - informs whether a graceful BOGUS is possible.
2. Try IOCTL_KGSL_GPUOBJ_IMPORT (type ADDR) with priv_len/flags variants.
3. Investigate whether _get_unmapped_area/mmap can place an entry at a chosen
   mid-range address with a wrapped size (unlikely: size bounded by memory).
4. Publish the confirmed finding (vuln + safe PoC + DoS) as-is.
