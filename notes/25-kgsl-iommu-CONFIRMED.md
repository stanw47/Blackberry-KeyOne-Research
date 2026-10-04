# KEYone — CONFIRMED: unpatched kgsl/IOMMU integer-overflow (CVE-2020-11261 / CVE-2023-33107)

Date: 2026-10-05
Status: **CONFIRMED PRESENT** in BlackBerry's own published kernel source.
Related: notes/19, 21, 23, 24.

## The confirmation
BlackBerry publishes GPL kernel source at `github.com/blackberry/android-linux-kernel`,
branches named `[platform]/[build]`. The msm8953 (KEYone) branch present is
**`msm8953/ABY299`** (a *later* 2019 build than our ABL766 / 2018-11).

Fetched `drivers/gpu/msm/kgsl_iommu.c` from that branch. The function:

```c
static int kgsl_iommu_set_svm_region(struct kgsl_pagetable *pagetable,
		uint64_t gpuaddr, uint64_t size)
{
	int ret = -ENOMEM;
	struct kgsl_iommu_pt *pt = pagetable->priv;
	struct rb_node *node;

	/* Make sure the requested address doesn't fall in the global range */
	if (ADDR_IN_GLOBAL(gpuaddr) || ADDR_IN_GLOBAL(gpuaddr + size))
		return -ENOMEM;

	spin_lock(&pagetable->lock);
	node = pt->rbtree.rb_node;

	while (node != NULL) {
		uint64_t start, end;
		struct kgsl_iommu_addr_entry *entry = rb_entry(node,
			struct kgsl_iommu_addr_entry, node);

		start = entry->base;
		end = entry->base + entry->size;

		if (gpuaddr  + size <= start)
			node = node->rb_left;
		else if (end <= gpuaddr)
			node = node->rb_right;
		else
			goto out;
	}

	ret = _insert_gpuaddr(pagetable, gpuaddr, size);
out:
	spin_unlock(&pagetable->lock);
	return ret;
}
```

## What the fixes added (both ABSENT here)
- **CVE-2020-11261 fix** introduced `iommu_addr_in_svm_ranges()` with a full
  `[gpuaddr, gpuaddr+size]` containment test. **Not present** — grep of the whole
  file for `addr_in_svm_ranges` returns nothing.
- **CVE-2023-33107 fix** added `u64 end = gpuaddr + size; if (end <= gpuaddr)
  return false;` (wraparound guard). **Not present.**
- The rbtree overlap test `if (gpuaddr + size <= start)` likewise has no overflow
  guard.

## Why ABY299 confirms ABL766
ABY299 (2019) postdates our ABL766 (2018-11) and still lacks the fixes, which only
landed in **Jan 2021** (CVE-2020-11261) and **Oct 2023** (CVE-2023-33107). The code
is therefore vulnerable on **every** msm8953 KEYone build, including ours.

## Reachability (proven live on our device)
- `/dev/kgsl-3d0` is `crw-rw-rw-` (`u:object_r:gpu_device:s0`) — opens from `shell`
  with **no SELinux denial** (verified: no AVC).
- `tools/kgsl_abi_probe` (aarch64 static, built with zig) ran on the device:
  - `open /dev/kgsl-3d0 = 3`
  - `GETPROPERTY type=1 size=40 -> OK`, `d0=0x0500060000000001` => **chipid 0x05000600
    = Adreno 506** — driver fully drivable from shell.
  - ioctl space recognized (nr=0x15 -> EOPNOTSUPP, nr=0x31/0x38/0x39/0x3a/0x40 -> 0,
    nr=0x48 -> ENOTSUPP), i.e. handlers execute.
- Entry paths both present: `kgsl_ioctl_map_user_mem` (memtype `KGSL_MEM_ENTRY_USER`)
  and `kgsl_ioctl_gpuobj_import` (type `KGSL_USER_MEM_TYPE_ADDR`) -> `_map_usermem_addr`
  -> `kgsl_setup_useraddr` -> `kgsl_setup_anon_useraddr` -> `kgsl_mmu_set_svm_region`
  -> `kgsl_iommu_set_svm_region`.

## Why grsec does not stop this
The primitive is **IOMMU page-table aliasing**, not slab reuse. The exploit flow
(Project Zero RCA, CVE-2023-33107) is:
1. Groom the IOMMU rbtree (UAF + OVERLAP + PLACEHOLDER ranges).
2. Race: insert a **BOGUS** range whose `gpuaddr+size` wraps -> passes the broken
   checks -> corrupts rbtree ordering.
3. `mmap()` an OVERLAP range -> `arm_lpae_map_sg` deletes the first PTE of the UAF
   range (unchecked `arm_lpae_init_pte` return; second related patch also absent in
   a 2018/2019 tree).
4. Free the UAF object -> dangling IOMMU PTEs (memory freed, PTEs not removed).
5. Shrink -> freed KGSL pages return to the page allocator; spray `task_struct`s.
6. GPU commands (via IOCTL_KGSL_GPU_COMMAND) read/write those pages through the
   dangling PTEs -> find a `task_struct` -> overwrite `addr_limit` with `KERNEL_DS`.

grsec's slab isolation does not apply; the bug yields kernel read/write through
the GPU's MMU.

## Caveats / difficulty
- The published RCA gives the full flow but **no public PoC code**; weaponizing it
  is a real research effort (race reliability, grooming, GPU command submission on
  the old SHAREDMEM/3.18 KGSL, and post-R/W cred handling under grsec).
- Our device is 3.18 (older KGSL than the 4.19 in the RCA); ioctl names differ
  (`GPUOBJ_IMPORT` may not exist; `MAP_USER_MEM` path is the equivalent per GHSL).
- Still: this is the first lead that is **reachable, unpatched, grsec-surviving,
  and publicly documented end-to-end.**

## Artifacts
- `tools/kgsl_probe.c`, `tools/kgsl_abi_probe.c` (aarch64, zig-built).
- BB source: `msm8953/ABY299` `drivers/gpu/msm/kgsl_iommu.c`.
- GHSL-2020-374 advisory; Project Zero CVE-2023-33107 RCA.
