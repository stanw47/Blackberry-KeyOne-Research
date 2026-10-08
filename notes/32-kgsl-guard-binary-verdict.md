# notes/32 — KGSL/io-pgtable "guard" verdict: ABSENT in the shipped ABL766 kernel

Date: 2026-10-08. Device: BBB100-3 (Sprint), build ABL766, kernel
`3.18.31-perf-gf38c8fb`. Binary studied: `artifacts/kernel.bin` (decompressed
boot image).

## Why this matters

`notes/26–31` concluded that the KGSL/IOMMU primitive (missing SVM range check)
was turned into **DoS-only** by an io-pgtable safety guard:

> `BUG_ON(!suppress_map_failures)` in `arm_lpae_init_pte` — selftest not
> compiled in → constant-folded to an unconditional BUG → corruption path
> panics.

That conclusion came from the **GPL source** (`ref/bb-kernel-msm8953-ABY299/
drivers_iommu_io-pgtable-arm.c:284-288`):

```c
	/* We require an unmap first */
	if (*ptep & ARM_LPAE_PTE_VALID) {
		BUG_ON(!suppress_map_failures);
		return -EEXIST;
	}
```

ABY299 is **not the build the device runs**. This note checks the shipped
ABL766 binary directly.

## Method (now reproducible)

1. `tools/kallsyms3.py artifacts/kernel.bin SYMBOL` — new resolver for this raw
   image (the stock vmlinux-to-elf path failed). Layout: token_table
   `0x10BED00`, token_index `0x10BF100`, num_syms `0xF38800`, names `0xF38900`,
   addresses `0xE40658..0xF38800` (127,029 u64, ascending).
2. VA → file offset: `file = VA - 0xffffffc000080000` (verified on
   `kallsyms_lookup_name`, `kgsl_iommu_set_svm_region`, `io_pgtable_exit`).
3. Opcode scan for ARM64 `BRK`: `(word & 0xFFE0001F) == 0xD4200000`.

## Evidence

Symbols resolved in the live image:

| symbol | VA | file off |
|---|---|---|
| `io_pgtable_exit` … `arm_32_lpae_alloc_pgtable_s1` | `0x9fa7dc`–`0x9fc0d0` | `0x97a7dc`–`0x97c0d0` |
| `arm_lpae_init_pte.isra.4` | `0x9fb99c` | `0x97b99c` |
| `__arm_lpae_map` | `0x9fba68` | `0x97ba68` |
| `arm_lpae_map` | `0x9fbaac` | `0x97baac` |
| `kgsl_iommu_set_svm_region` | `0x521b80` | `0x4a1b80` |
| `kgsl_iommu_addr_in_range` | `0x520254` | `0x4a0254` |

`brk` scan results:

| range | bytes | `brk` count |
|---|---|---|
| io-pgtable code (`0x97a7dc`–`0x97c0d0`) | 6,388 | **0** |
| `arm_lpae_init_pte.isra.4` | 204 | **0** |
| `__arm_lpae_map` / `arm_lpae_map` | 68 / 608 | **0** |
| KGSL cluster (`0x480000`–`0x4c0000`) | 256 KiB | 135 |
| early kernel text (`0x2000`–`0x9fa000`) | ~10 MB | 2,230 |

BUG/WARN machinery is clearly present in this kernel, yet **not a single `brk`
exists in the io-pgtable code**. If ABL766 had been built from the ABY299
source, `BUG_ON(!suppress_map_failures)` (and the `WARN_ON`s at
io-pgtable-arm.c:377/637/1071-1088) would each emit a `brk`.

`iommu_addr_in_svm_ranges` — the 2021/2023 Qualcomm fix — is also absent from
the symbol table, consistent with the unpatched range check in
`kgsl_iommu_set_svm_region` (0 `brk` in that function).

## Conclusion

**The io-pgtable guard is not in the shipped ABL766 kernel.** Overlapping maps
in `arm_lpae_init_pte` return `-EEXIST` cleanly; they do not hit an
unconditional BUG. `notes/31`'s "guard stands" is corrected — it described a
different (later/other) build's source, not the device.

The `pstore` capture from the global-overlap panic is truncated (8 KiB ring):
it shows only the secondary-CPU idle backtrace, the taint, and the watchdog
reboot — no BUG line. That is consistent with a **corruption-driven** panic
(clobbered GPU global PTEs), not a guard trip.

## Implications

- The stated blocker on the KGSL chain ("guard → BUG → DoS only") is invalid
  for this build. The primitive is still not proven exploitable — the
  global-overlap crash shows corruption is easy but uncontrolled.
- The next step is a **targeted corruption**: use the missing range check and
  `kgsl_iommu_set_svm_region`/`kgsl_mmu_map` without clobbering the global
  region, and convert the overlap into controlled PTE writes.
- Note the ABY299 source shows later builds added the guard — exploitability is
  build-specific and ABL766 is on the permissive side.

## Files

- `tools/kallsyms3.py` — symbol resolver for `kernel.bin`.
- `ref/bb-kernel-msm8953-ABY299/drivers_iommu_io-pgtable-arm.c` — reference
  source with the guard (NOT the shipped build).
- `artifacts/kernel.bin`, `artifacts/pstore_*.bin` (local, gitignored).
