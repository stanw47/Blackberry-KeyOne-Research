# KEYone — kgsl chain progress (grooming + safe wraparound)

Date: 2026-10-05
Related: notes/26, 27; docs/KEYone-kgsl-IOMMU-vulnerability.md.

## 1. Grooming primitives work (safe, verified live)
tools/kgsl_gpuobj_poc.c:
    GPUMEM_ALLOC_ID ret=0 id=1 gpuaddr=0x300000 mmapsize=0x1000
    mmap(offset=gpuaddr) = 0x265b61b000 ; wrote/read 0x41 ; GPUMEM_FREE_ID ret=0
=> allocate GPU buffers, mmap (offset=gpuaddr), read/write, free.

## 2. Safe wraparound demonstration (T4) — key result
tools/kgsl_bugA_poc.c now prints:
    T1 in-SVM-range      hostptr=0x700000000 len=0x1000 -> 0
    T2 out-of-SVM-range  hostptr=0x1dcc138000 len=0x1000 -> 0   <== MISSING SVM RANGE CHECK
    T4 wrap high+small   hostptr=0xfffffffffffff000 len=0x2000 -> -14  (-EFAULT, graceful)

T4 uses a HIGH hostptr + SMALL size: 0xfffffffffffff000 + 0x2000 wraps to 0x1000.
- ADDR_IN_GLOBAL(gpuaddr)=false; ADDR_IN_GLOBAL(gpuaddr+size) sees wrapped 0x1000=false
  -> global check BYPASSED -> _insert_gpuaddr inserts the BOGUS rbtree entry.
- memdesc_sg_virt -> get_user_pages(0xfffffffffffff000) fails -EFAULT (addr above
  TASK_SIZE) -> graceful cleanup, entry removed.
This reaches the wraparound/rbtree-corruption mechanism WITHOUT the huge allocation
that made the original huge-length T3 panic. Device uptime intact.

Why T3 (len=0xfffffffffffff000) panicked: memdesc_sg_virt computes
sglen=size/PAGE_SIZE, rejects only sglen>=LONG_MAX; sglen=0xfffffffffffff passes and
it tries kgsl_malloc(sglen*8) ~9 EB -> panic. High-addr/small-size avoids it.

## 3. Remaining chain work
1. Determine whether shipped ABL766 arm_lpae_init_pte has
   BUG_ON(!suppress_map_failures) (ABY299 source does). Dynamic test (panic =
   guard present, recoverable) or alternative primitive.
2. Grooming + race harness: allocate UAF/OVERLAP/PLACEHOLDER, mmap them, race
   MAP_USER_MEM with the T4-style BOGUS range, mmap OVERLAP, detect corruption.
3. GPU command submission on 3.18 KGSL (dangling-PTE R/W).
4. Post-R/W privilege handling under grsecurity/PaX + SELinux.

## Artifacts
- tools/kgsl_gpuobj_poc.c, tools/kgsl_bugA_poc.c (T1/T2/T4 safe; T3 disabled),
  tools/kgsl_probe.c, tools/kgsl_abi_probe.c.
