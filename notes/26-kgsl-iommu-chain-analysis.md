# KEYone — kgsl IOMMU chain: complete analysis + trigger recipe

Date: 2026-10-05
Related: notes/24, notes/25.
Sources: BlackBerry GPL kernel `blackberry/android-linux-kernel` branch
`msm8953/ABY299` (files pulled to `%TEMP%\bbsrc\`).

## 1. The two bugs, source-confirmed

### Bug A — kgsl_iommu_set_svm_region (CVE-2020-11261 / CVE-2023-33107)
drivers/gpu/msm/kgsl_iommu.c:
```c
static int kgsl_iommu_set_svm_region(struct kgsl_pagetable *pagetable,
		uint64_t gpuaddr, uint64_t size)
{
	/* Make sure the requested address doesn't fall in the global range */
	if (ADDR_IN_GLOBAL(gpuaddr) || ADDR_IN_GLOBAL(gpuaddr + size))
		return -ENOMEM;                       /* start+end only, no wraparound guard */
	...
	while (node != NULL) {
		...
		if (gpuaddr + size <= start)          /* no overflow guard */
			node = node->rb_left;
		else if (end <= gpuaddr)
			node = node->rb_right;
		else
			goto out;
	}
	ret = _insert_gpuaddr(pagetable, gpuaddr, size);   /* inserts bogus entry */
```
- No `iommu_addr_in_svm_ranges()` (the CVE-2020-11261 fix) anywhere.
- No `end <= gpuaddr` wraparound guard (the CVE-2023-33107 fix).
- Constants: KGSL_IOMMU_GLOBAL_MEM_BASE=0xf8000000, SIZE=SZ_8M,
  SVM64 range 0x700000000..0x800000000.

### Bug B — arm_lpae_map_sg unchecked arm_lpae_init_pte
drivers/iommu/io-pgtable-arm.c line ~507:
```c
if (ms.pgtable && (iova < ms.iova_end)) {
	arm_lpae_iopte *ptep = ms.pgtable + ARM_LPAE_LVL_IDX(...);
	arm_lpae_init_pte(data, iova, phys, prot, MAP_STATE_LVL,
			  ptep, ms.prev_pgtable, false);   /* return NOT checked */
	ms.num_pte++;                                      /* incremented anyway */
}
```
arm_smmu_map_sg (arm-smmu.c) bails on partial map and calls arm_smmu_unmap over
the counted range -> deletes PTEs that were never (re)written.

### Hardening caveat (IMPORTANT)
arm_lpae_init_pte has:
```c
if (*ptep & ARM_LPAE_PTE_VALID) {
	BUG_ON(!suppress_map_failures);   /* panic if false */
	return -EEXIST;
}
```
suppress_map_failures is only set true inside the pgtable SELFTEST
(lines 1199/1204); it is false at init and during normal operation. So on this
ABY299 tree, hitting an existing PTE in the arm_lpae_map_sg fast path would
BUG() (panic) rather than silently return -EEXIST. The Project Zero RCA's
PTE-deletion technique therefore may not transfer as-is; it must be checked
against the shipped ABL766 binary (older than ABY299 — the BUG_ON may have been
added later, in which case ABL766 lacks it and the technique works).

## 2. Reachability — live-confirmed
- /dev/kgsl-3d0 = crw-rw-rw-, u:object_r:gpu_device:s0, opens from shell, no AVC.
- GETPROPERTY type=1 size=40 returns chipid=0x05000600 (Adreno 506).
- All needed ioctls present (uapi msm_kgsl.h): MAP_USER_MEM 0x15,
  DRAWCTXT_CREATE 0x13, GPUMEM_ALLOC_ID 0x34, GPUMEM_FREE_ID 0x35,
  GPUMEM_GET_INFO 0x36, SUBMIT_COMMANDS 0x3D, GPUOBJ_ALLOC 0x45,
  GPUOBJ_FREE 0x46, GPUOBJ_INFO 0x47, GPUOBJ_IMPORT 0x48, GPU_COMMAND 0x4A.

## 3. Trigger recipe (Bug A via MAP_USER_MEM)
kgsl_ioctl_map_user_mem -> _map_usermem_addr -> kgsl_setup_useraddr ->
kgsl_setup_anon_useraddr -> kgsl_mmu_set_svm_region -> Bug A.

struct kgsl_map_user_mem (64-bit: 48 bytes):
  int fd;            // -1
  u64 gpuaddr;       // in/out
  u64 len;           // size
  u64 offset;        // 0
  u64 hostptr;       // user VA -> becomes gpuaddr when USE_CPU_MAP
  u32 memtype;       // KGSL_USER_MEM_TYPE_ADDR = 2
  u32 flags;         // must include KGSL_MEMFLAGS_USE_CPU_MAP = 0x10000000

Requirements (from source):
- hostptr != 0, page-aligned; offset == 0; size page-aligned.
- KGSL_MEMFLAGS_USE_CPU_MAP set and kgsl_mmu_use_cpu_map(mmu) true.
- memtype = KGSL_USER_MEM_TYPE_ADDR (2) -> KGSL_MEM_ENTRY_USER -> _map_usermem_addr.
- Bug triggers when hostptr + len wraps (or spans the 8 MB global region) while
  neither hostptr nor hostptr+len lands inside [0xf8000000, 0xf8800000) —
  e.g. hostptr=0x700204000, len=0xffffffffffefd000.

Equivalent path: IOCTL_KGSL_GPUOBJ_IMPORT (type ADDR) -> _gpuobj_map_useraddr ->
kgsl_setup_useraddr.
mmap() path (OVERLAP step): kgsl_get_unmapped_area -> _gpu_set_svm_region ->
kgsl_mmu_set_svm_region (same Bug A).

## 4. Full chain (from Project Zero RCA, CVE-2023-33107)
1. Allocate UAF + PLACEHOLDER via GPUOBJ_ALLOC, mmap() them (rbtree + PTEs).
2. Race MAP_USER_MEM with BOGUS wraparound range -> bogus rbtree entry.
3. mmap() OVERLAP -> arm_lpae_map_sg -> unchecked init_pte -> first PTE of UAF deleted.
4. GPUOBJ_FREE UAF -> arm_lpae_unmap bails at zero PTE -> dangling PTEs.
5. Shrink -> freed KGSL pages to page allocator -> spray task_structs.
6. GPU_COMMAND via dangling PTEs -> R/W freed pages -> overwrite
   task_struct->addr_limit = KERNEL_DS.

## 5. Status / next steps
- Bug A: confirmed present; trigger recipe known; reachable.
- Bug B: present (unchecked return) but gated by BUG_ON(!suppress_map_failures)
  in ABY299 — must be checked against the shipped ABL766 binary, or bypassed by
  an alternative use of the rbtree corruption.
- Weaponization (race reliability, rbtree grooming, GPU command submission on the
  3.18 SHAREDMEM-era KGSL, post-R/W cred handling under grsec) is a substantial
  effort.
- Recommended next: (a) disassemble the shipped kernel.bin arm_lpae_map_sg to see
  if the BUG_ON is present; (b) build a SAFE PoC that triggers only Bug A's bogus
  rbtree insertion (no overlapping PTE) and observes the ioctl return, proving the
  range-check bypass without risking a panic; (c) only then attempt the overlap
  step.

## Artifacts
- %TEMP%\bbsrc\ — kgsl.c, kgsl_mmu.c, kgsl_iommu.c, kgsl_ioctl.c, arm-smmu.c,
  io-pgtable-arm.c (ABY299).
- tools/kgsl_probe.c, tools/kgsl_abi_probe.c.
- %TEMP%\opencode\kernel.bin — decompressed stock ABL766 kernel.
