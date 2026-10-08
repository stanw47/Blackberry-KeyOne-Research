# notes/55 — KGSL T5/T6 live results: overlap-creation route is blocked (panic)

Date: 2026-10-09 night → 2026-10-10. Device: BBB100-3 ABL766.
Related: notes/24–32, notes/54. Tools: `tools/kgsl_t5_rbtree.c`
(build `kgsl_t5_rbtree`, `kgsl_t6_rbtree` with `-DDO_T6`).

## T5 — insert-without-rollback confirmed live (SAFE, no panic)

Flow: open kgsl → anon map @0x700100000 → map_usermem(victim A) →
bogus wrapped insert → overlap control probe.

Observed:

```
[1] anon mmap @0x700100000 = 0x700100000
[2] victim A map_usermem -> 0            (A registered + PTEs)
[3] bogus wrapped insert -> -14          (hostptr=0xFFFFFFFFFFFFF000, len=0x2000)
[4] control overlap probe -> -12         (overlap still rejected)
[*] done; close fd
```

Source match (`ref/…/drivers_gpu_msm_kgsl.c`):

- `kgsl_setup_anon_useraddr()` calls `kgsl_mmu_set_svm_region()` (inserts the
  range into the pagetable rbtree) and **returns an error later** if
  `memdesc_sg_virt()` fails (hostptr invalid → `get_user_pages` -EFAULT) —
  **no rollback of the rbtree entry**.
- `memdesc_sg_virt()`: `sglen = size/PAGE_SIZE`; `kgsl_malloc(sglen*8)`
  (`vmalloc` for > PAGE_SIZE) *before* `get_user_pages` — so small bogus
  lengths fail cleanly.

Result: persistent bogus bookkeeping entry inside the process pagetable
(T5 safe; process teardown cleans it).

## T6 — huge-len overlap insert: **PANIC (reproduces T3)**

`map_usermem(hostptr=0xFFFFFFFFFFFFF000, len=0x700102000)` — a range whose
wrapped end lands at 0x700101000, mathematically containing victim A, so the
broken rbtree walk (`gpuaddr+size <= start`) misroutes and inserts it.

Observed: output stops at the T6 line; adb loses the device; device reboots
(clean, data intact). This reproduces the historical T3 panic exactly
("huge-length wraparound panics this kernel").

## Why the mmap-path alternative does not rescue it

`kgsl_get_unmapped_area` → `get_mmap_entry()` requires, for cpu-map entries,
**`len == kgsl_memdesc_footprint(entry)`** (`-ERANGE` otherwise). A bogus range
that contains SVM victim A needs `len > ~0x700103000` (28 GB) ⇒ the backing
gpuobj would need a 28 GB footprint (allocation impossible). Smaller lengths
insert cleanly but their wrapped sets (`[~0, len-wrap)` ∪ `[hostptr, 2^64)`)
never contain a real SVM victim, so no overlap is created.

⇒ The RCA's BOGUS/OVERLAP rbtree grooming step is **not reachable** with the
primitives available on this kernel:
- small bogus inserts: safe but useless (no overlap);
- huge bogus inserts (the only ones that overlap): panic in the
  `memdesc_sg_virt` → vmalloc/get_user_pages path.

## Where the KGSL chain stands

- Reachable, live-confirmed: missing SVM-range/global-span checks
  (`kgsl_iommu_set_svm_region`), persistent bogus rbtree insertion (T5).
- Blocked: the specific corruption primitive from CVE-2023-33107 (PTE deletion
  via overlap) requires overlap creation, which panics here before any
  corruption can be used.
- Remaining options for the kernel/root lane:
  1. **CVE-2020-11179** — KGSL ring-buffer pointer race, MSM8953-listed with a
     public PoC (sparrow-labz). Different primitive; worth assessing against
     this build before more IOMMU work.
  2. Sweep the 3.18-era KGSL for other missing checks that yield **bounded**
     corruption (no huge allocations), or use the T5 bookkeeping corruption in
     a way that does not need overlap (e.g., effects on `_search_range` —
     careful: `BUG_ON(gpu >= cpu)` there is a panic trap).
  3. Revisit non-KGSL kernel surfaces (grsec constrains slab classes but not
     IOMMU/GPU paths).

## Guardrails reconfirmed

- Huge-len wraparound ⇒ panic. Small wrapped insert ⇒ safe.
- After any bogus insert, avoid hint-less mmaps (`_search_range` has
  `BUG_ON(gpu >= cpu)`); close the fd promptly.
- Each panic reboots the device cleanly (verified again: Android back, data
  intact).
