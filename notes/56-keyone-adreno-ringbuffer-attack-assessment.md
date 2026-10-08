# notes/56 — Adreno ringbuffer attack (CVE-2019-10567 / CVE-2020-11179) assessed for ABL766

Date: 2026-10-10. Device: BBB100-3 ABL766, kernel 3.18.31 (Dec 2018).
Sources: P0 blog "Attacking the Qualcomm Adreno GPU" (Ben Hawkes, 2020-09-08);
sparrow-labz `CVE-2020-11179-Adreno-Qualcomm-GPU` (adrenaline.c, PoC for sargo);
Guang Gong USENIX-2020 whitepaper (original CVE-2019-10567 chain).
Local references: `ref/bb-kernel-msm8953-ABY299/drivers_gpu_msm_adreno_ringbuffer.c`,
`…_adreno.c`, `…_adreno_a5xx.c`, `…_adreno_dispatch.c`.

## Mechanism (from the blog)

- The GPU shares a "scratch" global mapping (1 page, present in every GPU
  context pagetable, writable by user GPU commands).
- `adreno_get_rptr()` (adreno.c:179) reads the ringbuffer RPTR from
  `device->scratch + SCRATCH_RPTR_OFFSET(id)` (`id*4`) for non-a3xx.
- `adreno_ringbuffer_allocspace()` (adreno_ringbuffer.c:156) uses that value
  with two comparisons (`rptr <= _wptr`, `_wptr+dwords < rptr`) to hand out RB
  space. Corrupting scratch→RPTR desyncs CPU/GPU ringbuffer state and lets the
  CPU allocate space that **overlaps commands the GPU has not yet executed**.
- The attacker then overwrites ringbuffer operations with chosen legitimate
  ops during a protected-mode-off window (context switch / preemption), e.g.
  replacing the context switch with a `CP_INDIRECT_BUFFER` to attacker cmds,
  which then rewrite the SMMU `TTBR0` to attacker page tables → arbitrary
  physical R/W → kernel patch → root.

## Applicability to ABL766 (confirmed)

| item | status on our build |
|---|---|
| `adreno_get_rptr` reads RPTR from scratch (`+4*id`) | **present** (source; symbol present in kernel.bin) |
| `adreno_ringbuffer_allocspace` vulnerable logic | **present** (identical to blog's quote) |
| scratch allocated with flags=0 → **no GPU-address randomization** | **confirmed** (ABY299 source line 280; our Dec-2018 build predates the Sep-2019 patch) |
| a5xx preemption with `CP_SET_PROTECTED_MODE 0 … 1` + `CP_CONTEXT_SWITCH_YIELD` | **present** (`a5xx_preemption_pre_ibsubmit` symbol 0x53e1d8; `_preemption_init` in a5xx source) |
| profiling pre/post-IB processing (`adreno_profile_preib_processing`, …) | **present** (pre-Sep-2019 ⇒ original CVE-2019-10567 smuggling path may also exist, potentially simpler) |
| Fixes | none — build Dec 2018 < Sep 2019 (10567) < Aug 2020 (11179) |

Extra advantage: our scratch GPU VA is **fixed** (not randomized), so the
blog's address-recovery step (bruteforce / preemption spill) is unnecessary if
the deterministic global layout can be computed.

## Why this lane beats the IOMMU route

- Bounded: no huge allocations, no wraparound arithmetic → none of the panic
  classes hit in notes/55.
- P0: "a failed attempt has no observable negative effects" — the race can be
  retried in a loop (≥20% per attempt on sargo).
- Uses the same world-accessible `/dev/kgsl-3d0` and the ioctls already
  confirmed present (DRAWCTXT_CREATE, GPU_COMMAND 0x4A, SUBMIT_COMMANDS 0x3D).

## Exploit stages / next work items

0. **GPU command-submission harness** (first build target): create draw context,
   allocate a command buffer via GPUMEM_ALLOC_ID + mmap, submit with
   `IOCTL_KGSL_GPU_COMMAND`; validate with `CP_MEM_WRITE` to a user buffer +
   CPU readback. (a5xx CP packet encoders from `adreno_a5xx.c` helpers.)
1. **Scratch base**: compute from the deterministic global allocator
   (`kgsl_iommu` globals; base 0xf8000000, 8 MB region) — or recover by
   bruteforce over non-live pages; verify by writing the RPTR and observing
   `allocspace` behaviour (e.g., RB getspace returning overlapping regions).
2. **RPTR corruption**: `CP_MEM_WRITE` scratch+4*id.
3. **RB overwrite + race**: target the a5xx preemption/context-switch
   protected-mode-off window; overwrite with `CP_INDIRECT_BUFFER` to attacker
   commands.
4. **TTBR0 rewrite** → fake page tables → physical R/W → kernel patch → root.
   Needs a5xx SMMU/TTBR0 register offsets (a5xx source) and a physical-page
   spray for the fake tables.

## Immediate next step

Build `tools/kgsl_gpu_submit.c` (stage 0) and validate GPU command execution
from `shell` on the live device. Then stage 1 (scratch base).

## Stage 0 — DONE (live, 2026-10-10)

`tools/kgsl_gpu_submit.c` runs on the device (static aarch64, zig):

```
[2] DRAWCTXT_CREATE ret=0 id=11          (flags=0x12: PREAMBLE|NO_GMEM_ALLOC —
                                          required by adreno_drawctxt_create,
                                          flags=0 -> -EINVAL)
[3] alloc CMD gpu=0x300000   [4] alloc OUT gpu=0x301000
[5] mmap CMD/OUT OK          (mmap offset = id<<12; non-cpu-map pgoff = mem id)
[6] GPU_COMMAND ret=0
[7] readback d0=0x42424242 d1=0x43434343  <== GPU COMMANDS WORK
```

- Packet encoders validated: exact `cp_type7_packet` layout (odd-parity bits
  at 15/23) + `cp_gpuaddr` low/high + `CP_MEM_WRITE` (0x3d) + `CP_NOP` (0x10).
- Cache maintenance: `dc civac` + `dsb ish` both directions works.
- Command object: `{offset=0, gpuaddr, size, flags=KGSL_CMDLIST_IB, id}`;
  objlist optional (numobjs=0 OK).

Next: stage 1 — scratch base. Offline: derive the global allocation layout
from `kgsl_iommu.c`/`adreno*.c` probe order (base per notes/26:
`KGSL_IOMMU_GLOBAL_MEM_BASE=0xf8000000`, 8 MB). Live: detect candidates with
**read-only `CP_MEM_TO_MEM`** probes (copy candidate dword into our OUT buffer;
a scratch page has rb0 RPTR at offset 0 — small 4-aligned values), avoiding
blind writes into the global region.

## Stage 1 — DONE (live, 2026-10-10): scratch = 0xf8009000

- `kgsl_scratch_scan.c`: `CP_MEM_TO_MEM` is **not usable on a5xx** (all
  encodings accepted, nothing copied — opcode 0x3b is gen-specific); file kept
  for the record.
- `kgsl_scratch_verify.c`: write→wait→marker oracle:
  `CP_MEM_WRITE(C+0x100, MAGIC)` → `CP_WAIT_REG_MEM[0x13, C+0x100, MAGIC, mask,
  1]` → `CP_MEM_WRITE(OUT, 1)`; marker appears only if the write landed,
  persisted and was observable. No fault on the right page.
- **Result: `[2] cand 0xf8009000 <== WRITABLE+PERSISTENT`** — device alive.
- Layout confirmed (bump allocator, kgsl_iommu.c:200):
  `setstate @0xf8000000` (4K, GPUREADONLY) → `memstore @0xf8001000` (32K) →
  **`scratch @0xf8009000`** (4K, writable) → per-RB descriptors from 0xA000
  (`pagetable_desc` 4K, `buffer_desc`/ringbuffer 32K per RB).
- `CP_WAIT_REG_MEM` proven encoding (from the public PoC):
  `pkt7(0x3c,6)` + `[0x13, addr_lo, addr_hi, ref, 0xffffffff, 0x1]`.
- Scratch usage in this build (source-confirmed): only offsets 0..15
  (`SCRATCH_RPTR_OFFSET(id) = id*4`) — offset 0x100 free for testing.

Next: **stage 2 — RPTR desync**. Write rb0 RPTR (`scratch+0`) to a chosen
value (PoC uses 0x1ffc for a 8192-dword RB) and observe `allocspace` behaviour.
Hazard: a wrong value can wedge that ringbuffer's allocation until the GPU
rewrites the RPTR; choose the least-used RB, keep critical work off it, and
close the fd promptly. RB0's ringbuffer mapping is expected at `0xf800b000`
(32K) if we need to target ringbuffer contents.


