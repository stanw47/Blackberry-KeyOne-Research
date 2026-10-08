# notes/54 — KGSL lane re-opened: shipped-kernel recon (2026-10-09 night)

Date: 2026-10-09. Device: BBB100-3 ABL766, kernel `3.18.31-perf-g38c8fb`.
Related: notes/24–32 (KGSL chain), notes/32 (guard absent verdict), notes/53
(factory mode requires code exec → root).
User direction: pursue the non-fastboot (kernel) path; acknowledged risk =
kernel panics are the historical failure mode (Priv + KEYone).

## Why now

- notes/32 proved the io-pgtable BUG_ON guard is **absent** in the shipped
  ABL766 binary (0 `brk` in io-pgtable; `-EEXIST` returns cleanly). The RCA
  (CVE-2023-33107) technique is therefore not categorically blocked.
- The global-overlap panic (notes/30) is *corruption-driven* (clobbered GPU
  globals/setstate), not guard-driven — so a *targeted* overlap that avoids the
  global region should not panic.

## New tooling / recon done this session

- `tools/kern_disasm.py` — AArch64 disassembler for the raw Image
  (VA→file: `file = VA - 0xffffffc000080000`).
- `tools/kallsyms3.py` symbol resolution re-run for the full chain; addresses:

  | symbol (as resolved) | VA | note |
  |---|---|---|
  | `kgsl_iommu_set_svm_region` | `0x521b80` | vulnerable check |
  | `_insert_gpuaddr.isra.22` | `0x52197c` | rbtree insert |
  | `arm_lpae_map_sg` | `0x9fbd0c` | **name sus** — this address is an ops/alloc fn; the real map_sg looks like `0x9fbaac` |
  | `__arm_lpae_map` | `0x9fba68` | looks like an sg→phys helper, not the map |
  | `arm_lpae_init_pte.isra.4` | `0x9fb99c` | matches notes/32 |
  | `arm_smmu_map_sg` | `0xa09f40` | per name |
  | `kgsl_mmu_map` | `0x51cbe0` | per name |

  **Caveat:** several kallsyms3 resolutions are off-by-a-neighbor (names are
  fuzzy). Anchor functions by structure/disassembly, not by name.

- Shipped `arm_lpae_map_sg` disassembled at `0x9fbaac` (sglist walk → u64 phys
  array → batched map state `{iova, size, attr, 0x200c12…}` → helpers
  `0x099ef0`, `0x445c80`, `0x445e64`). No `brk` anywhere (guard absent,
  consistent with notes/32). The direct `arm_lpae_init_pte` call site is not a
  simple `bl` in this build — the mapping is batched, so the RCA's unchecked
  return must be re-located in this flow before writing the PoC.
- `ref/lk_msm8953/` is **generic CodeAurora LK** (no authboot/securewipe) —
  useful only as a base reference for the bootloader lane; BB's aboot stays
  binary-only.

## Plan (incremental, panic-minimizing)

1. **Map ABY299 source to shipped code**: read
   `ref/bb-kernel-msm8953-ABY299/drivers_iommu_io-pgtable-arm.c` +
   `drivers_iommu_arm-smmu.c` and match to the shipped disassembly
   (`0x9fbaac` flow, `0x9fb99c`, `0xa09f40`), noting every place a returned
   error is dropped (the RCA bug class).
2. **Safe primitive checks on-device** (already have T1/T2/T4 PoCs):
   - T2 (out-of-SVM accepted) — no panic; confirms bug A reachable.
   - New T5: BOGUS wraparound range insertion into the rbtree **without**
     mapping anything (bookkeeping-only) — expected no panic; proves the
     rbtree corruption path.
3. **PTE-deletion step, user-owned buffers only** (never globals): two GPU
   buffers (victim + overlap) → delete one victim PTE → verify the PTE is gone
   via iova_to_phys/GPU access → no panic expected if the targeted range avoids
   globals.
4. Only if (3) is clean: UAF/free + page-spray + `task_struct->addr_limit`
   overwrite (the RCA endgame) — the long pole (grooming, race reliability,
   3.18 SHAREDMEM-era GPU command submission).
5. Post-R/W: grsec/PaX + SELinux handling remains the final unknown.

## Guardrails

- Never overlap the global region (known panic).
- One change per test; pstore capture after any reboot (8 KiB ring is
  truncated — consider raising pstore size if possible).
- Device may panic by design of intermediate steps; recovery = reboot
  (verified safe, data intact).
