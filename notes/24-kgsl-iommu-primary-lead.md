# KEYone — PRIMARY LEAD: kgsl/IOMMU range-check bug (CVE-2020-11261 class)

Date: 2026-10-05
Related: notes/19 (kernel survey), notes/23 (patch rationale).

## The lead
**CVE-2020-11261 (GHSL-2020-374)** — "Incorrect bounds checking in Qualcomm kgsl
driver." Qualcomm's wording: *"Memory corruption due to improper check to return
error when user application requests memory allocation of a huge size."*
- **CISA Known Exploited Vulnerabilities catalog** — exploited in the wild.
- Fixed **January 2021** bulletins.
- **Impact: kernel code execution from a userspace application.**
- Reachable via `IOCTL_KGSL_MAP_USER_MEM` on **`/dev/kgsl-3d0`**.

## Why this is the best lead for the KEYone
1. **Reachable with no gate.** `/dev/kgsl-3d0` is `crw-rw-rw-` (0666) on this
   device — shell (uid 2000) and any app can open it. No SELinux type, no group.
2. **Not grsec-blocked.** The exploit derives kernel R/W from **IOMMU page-table
   aliasing** (mapping user memory over the GPU's global region), NOT from
   slab-reuse/UAF. grsec's slab isolation (which killed CVE-2019-2215 etc.) does
   not apply to this primitive. This is the class that historically survives.
3. **Patch level is 2+ years behind.** Our kernel build is **Nov 21 2018**; the
   fix landed **Jan 2021**. The vulnerable code is present.

## Confirmed on this device's kernel
Extracted `kernel.bin` from stock `boot.img` (gzip at 0x800; valid ARM64 Image;
banner `3.18.31-perf-gf38c8fb ... Nov 21 2018`).
`/proc/kallsyms` (167987 syms) confirms **every function in the exploit chain**:
```
kgsl_ioctl_map_user_mem
kgsl_ioctl_map_user_mem_compat
kgsl_setup_anon_useraddr
kgsl_mmu_set_svm_region
kgsl_iommu_set_svm_region      <- the vulnerable function
kgsl_iommu_addr_in_range       <- the (insufficient) check
kgsl_iommu_add_global / map_globals
```
Also present: `adreno_perfcounter_read_group`, `adreno_perfcounter_read`
(the separate CVE-2020-11179 "arbitrary read/write via ring buffer pointer race",
MSM8953-listed, public PoC by sparrow-labz).

## Root cause (from GHSL-2020-374)
`kgsl_iommu_set_svm_region(pagetable, gpuaddr, size)`:
```c
if (ADDR_IN_GLOBAL(pagetable->mmu, gpuaddr) ||
        ADDR_IN_GLOBAL(pagetable->mmu, gpuaddr + size))
    return -ENOMEM;
```
- Only checks the **start and end** against the global region
  `KGSL_IOMMU_GLOBAL_MEM_BASE64 = 0xfc000000`, size `20MB (0x1400000)`.
- **No check that the whole `[gpuaddr, gpuaddr+size]` avoids the global range.**
- Request a region **larger than the global region** -> it blankets the global
  range yet passes the start/end check -> **overlapping IOMMU mappings** ->
  attacker-controlled GPU page tables alias kernel/global memory -> R/W.
- The kernel image contains the constants `0xfc000000` and `0x1400000`, confirming
  this code is compiled in.

## Related GPU CVEs, all MSM8953-listed, all post-2018, all on /dev/kgsl-3d0
- CVE-2021-1905 — UAF, improper multi-process memory-mapping handling (8.4)
- CVE-2021-1906 — UAF on ION handles (6.2)
- CVE-2020-11179 — arbitrary R/W via ring-buffer pointer race (public PoC)
- CVE-2020-11239 — kgsl UAF (4.14+, likely N/A)
- CVE-2023-33107 — the "more likely vector" GHSL references for 11261

## Plan
1. `tools/kgsl_probe.c` (aarch64) — non-destructive probe:
   - open `/dev/kgsl-3d0`, GETPROPERTY, CONTEXT_CREATE
   - attempt the `IOCTL_KGSL_MAP_USER_MEM` / SVM path with parameters that
     *should* be rejected (oversized region crossing the global range), and
     observe whether the kernel returns success (bug present) or -ENOMEM (fixed).
   - No exploitation; purely a yes/no on the missing check.
2. If confirmed: study the CVE-2023-33107 RCA (Project Zero 0-day RCA) for the
   exact aliasing primitive, then determine whether a full chain is feasible on
   3.18/kgsl SHAREDMEM-era code.
3. Hardest part remains post-R/W: defeating SELinux + grsec creds, but kernel R/W
   typically yields `commit_creds`/`selinux_enforcing` overwrite.

## Honest caveats
- Requires writing and running a custom aarch64 binary as shell (we can: adb shell,
  compile with the proven aarch64 toolchain recipe from the Priv corpus).
- Full kernel R/W -> root is non-trivial on a grsec build, but kernel R/W is a
  *fundamentally different* position than the blocked UAF primitives.
- This is the first lead that is simultaneously **reachable, unpatched, and in a
  class that survives grsec.**
