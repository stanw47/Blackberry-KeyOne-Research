# notes/57 — Adreno stage 3 design: the a5xx protected-mode race

Date: 2026-10-10. Device: BBB100-3 ABL766. Related: notes/56.
Sources: `ref/bb-kernel-msm8953-ABY299/adreno_ringbuffer.c`, `adreno_a5xx.c`,
`adreno_a5xx_preempt.c` (downloaded), `adreno_dispatch.c`, `adreno.h`.

## What the driver writes into the ringbuffer (per submission)

`adreno_ringbuffer_addcmds()` (adreno_ringbuffer.c:395):

```
[CP_NOP, KGSL_CMD_IDENTIFIER]                          (always)
[a5xx_preemption_pre_ibsubmit]                         (22 dwords, preemption on)
      CP_PREEMPT_ENABLE_GLOBAL <0|2>
      CP_SET_PROTECTED_MODE 0          <-- window opens
      CP_CONTEXT_SWITCH_SAVE_ADDR_LO = preemption_desc.gpuaddr
      CP_CONTEXT_SWITCH_SAVE_ADDR_HI = preemption_desc.gpuaddr>>32
      CP_SET_PROTECTED_MODE 1          <-- window closes
      CP_PREEMPT_ENABLE_LOCAL <0|1>
      CP_YIELD_ENABLE 2
[memstore soptimestamp writes …]
[user command buffers: CP_INDIRECT_BUFFER_PFE(cmd_gpuaddr, dwords)
 for every entry of cmdbatch->cmdlist]                  (adreno_ringbuffer.c:983-995)
[global seq counter MEM_WRITE, CP_EVENT_WRITE CACHE_FLUSH_TS timestamps, …]
```

Key facts:

- User commands are **not copied** into the RB; the driver inserts
  `CP_INDIRECT_BUFFER_PFE` packets pointing at the user's GPU buffers.
- `KGSL_CMD_FLAGS_PMODE` (which would sandwich the copied user commands between
  `CP_SET_PROTECTED_MODE 0/1`) is defined but **has no setter in this build** —
  user commands always execute with protected mode on.
- The only protected-mode-off window in normal flow is inside
  `a5xx_preemption_pre_ibsubmit`: it programs the privileged CP registers
  `A5XX_CP_CONTEXT_SWITCH_SAVE_ADDR_LO/HI` (where the CP saves context state on
  a preemption). This is the KEYone counterpart of the blog's a6xx context
  switch window.

## The race (blog mechanism, ported)

Goal: cause the GPU to execute **our indirect-branch ops while protected mode
is still off**, i.e. overwrite the RB content starting at the
`CP_SET_PROTECTED_MODE 1` dword (or later within the window) with a *new
submission's* RB bytes so that the op that executes at that exact offset is a
`CP_INDIRECT_BUFFER_PFE` to attacker commands (and the re-enable is gone).

Facilitators we now have:

1. **RPTR control** (stage 2a): fake `scratch+0` to make
   `adreno_ringbuffer_allocspace()` hand out an allocation whose start
   overlaps the in-flight window instead of the true free area.
2. **Deterministic rb0 `_wptr`**: our context is pinned to rb0 (priority 1);
   every submission advances `rb->_wptr` by `total_sizedwords` (computed in
   addcmds: base 2 + preemption 22 + timestamps + PMODE/etc. + the IB list
   size). If we are the only rb0 user, `_wptr mod 8192` can be tracked exactly
   from a known baseline, so the landing offset of a new submission's bytes is
   computable — the blog's "calculate the correct layout of padding, payload
   and context switch".
3. **Stall/release primitive**: `CP_WAIT_REG_MEM` on a user-buffer flag stalls
   the GPU inside a submitted IB (from user memory) while the CPU races the
   next submission; release via a GPU-side write from the payload or via a
   preemption/context-switch event (blog used the context-switch machinery).
4. **Win detection**: payload ops execute with PM off; first probe =
   re-write `CONTEXT_SWITCH_SAVE_ADDR` to an attacker buffer and trigger
   preemption (`CP_CONTEXT_SWITCH_YIELD`), or (simpler, safe) execute a
   privileged no-op whose effect is observable through a marker write.

Fallback / endgame (stage 4): with PM off we can program SMMU/TTBR0
(`CP_SMMU_TABLE_UPDATE` / a5xx SMMU registers in `a5xx_reg.h`) to fake page
tables in a sprayed physical page → arbitrary physical R/W → kernel patch.

## Build plan (next)

1. `tools/kgsl_race_harness.c`:
   - rb0-pinned context (done in stage 2a), large cmd buffer (64 KB) for
     multi-batch streams.
   - `submit()` with controllable `sizedwords`; track `_wptr` per submission
     (formula + sanity check).
   - stall helper: IB writes flag=0 to a user dword, then
     `CP_WAIT_REG_MEM` for flag==0xFFFFFFFF; a second helper IB sets the flag.
   - rptr-fake helper (stage 2a code) executed as part of the racing IB.
2. First experiment (benign): arrange the window overwrite and use a
   **payload that writes a marker to our OUT buffer only if it ran** (e.g.,
   payload = MEM_WRITE marker; if PM-off branch happened, marker differs from
   the PM-on path). Iterate timing/bias until a win is detected, then report
   `win rate`.
3. Only after a reliable win: swap the payload for privileged register writes
   (SAVE_ADDR spoof + preemption) → stage 4.

## Hazards

- rb0 is shared with the system; wedging it can stall low-priority GPU work
  (recoverable; GPU reset on fault).
- A wrong landing offset may execute half-overwritten driver ops → GPU fault
  (recoverable). Keep payloads small and idempotent during bring-up.

## S3.0 result (live, 2026-10-10): cross-rb release does NOT work

`tools/kgsl_race_harness.c` (rb0 stall IB: flag=0, `CP_WAIT_REG_MEM` for
0xFFFFFFFF; rb2 release IB: flag=0xFFFFFFFF):

```
[2] stall submit ret=0
[3] stall entered -> yes
[4] release submit ret=0
[5] stall released -> NO
```

- A `CP_WAIT_REG_MEM` in a user IB is **not preemptible** by a higher-priority
  ringbuffer; the release command never ran. The stall was later cleared by the
  driver's own timeout/recovery (timestamp timeout → GPU reset), and the GPU
  works again (stage-0 re-verified OK).
- Implication: the race needs a *bounded* stall (wait on a condition the
  exploit itself satisfies) or no stall at all (rely on RB queue depth).
- Bonus discovered: **`dmesg` is readable from shell** → real-time KGSL
  fault/recovery monitoring for race tuning.

## Profiling route (original CVE-2019-10567) — status

- Full kallsyms dump (127,029 symbols) written to
  `recon/kallsyms-abl766.txt` (from `artifacts/kernel.bin`).
- The shipped kernel contains **none** of the IB-based profiling helpers
  (`_ib_cmd_mem_write`, `_ib_cmd_reg_to_mem`, `_build_pre_ib_cmds`,
  `_create_ib_ref`, `adreno_profile_assignments_ready`) and no `shared_buffer`
  global name string → strongly suggests the **pre-fix implementation that
  writes profiling PM4 directly into the ringbuffer** (the CVE-2019-10567
  smuggling primitive), i.e. no race needed.
- Caveat found late: kallsyms3 name mapping is **unreliable for the
  adreno_profile/ringbuffer address cluster** (functions at the named addresses
  do not match the expected shapes; likely a name-decode/ordering issue). Must
  re-anchor by code structure (e.g., scan the `addcmds` caller for calls into
  the 0x548xxx cluster, or match the perfcounter ioctl path) before building
  the ioctl harness.
- Next: reliable anchor for `adreno_profile_preib_processing` /
  `adreno_perfcounter_read_group`, then:
  1. create perfcounter assignments (`IOCTL_KGSL_PERFCOUNTER_GET` 0x38 etc.),
  2. confirm profile pre-IB dwords appear in the RB (via RPTR desync + WAIT
     probes),
  3. align execution so those dwords run as ops (misaligned-entry smuggle).

## BREAKTHROUGH (live, 2026-10-10): arbitrary dword into rb0 via perfcounter GET

`tools/kgsl_perfcounter_probe.c`:

```
[2] QUERY group CP ret=0 count=16
[3] GET custom countable (0x41414141) ret=0 offset=0x3ae offset_hi=0x3af
[4] READ ret=0 value=0x11866
[5] PUT ret=0
```

- `adreno_perfcounter_get()` accepts an arbitrary **new** `countable` (non-fixed
  CP group): it assigns an empty counter slot and calls
  `adreno_perfcounter_enable()` → `_perfcounter_enable_default()` which does:

  ```c
  rb = &adreno_dev->ringbuffers[0];              // rb0!
  cmds += cp_wait_for_idle(adreno_dev, cmds);
  *cmds++ = cp_register(adreno_dev, reg->select, 1);   // type4 header
  *cmds++ = countable;                                 // <-- USER DWORD
  adreno_ringbuffer_issuecmds(rb, 0, buf, cmds-buf);
  ```

- `adreno_ringbuffer_issuecmds()` = `addcmds(rb, flags|KGSL_CMD_FLAGS_INTERNAL_ISSUE,
  cmds, sizedwords, 0, NULL)` → the inserted RB block framing is exactly the
  normal addcmds layout (NOP+identifier, pre_ibsubmit 22 dw, internal
  identifier, timestamps, **our 3 dwords**, seq write, cache-flush timestamp).

So: **unprivileged shell can inject a fully attacker-chosen 32-bit dword into
rb0's command stream, at a computable offset within each insertion block**
(repeatable per GET, each new countable = one more controlled dword, slot
reusable via PUT). Together with RPTR control (notes/56 stage 2a) this is the
complete CVE-2019-10567 smuggling primitive — no race needed.

Old-vs-fix status: the shipped kernel's perfcounter path matches the pre-fix
2017 code (`ref/adreno_perfcounter_3.18.c`); the Sep-2019 fix ("execute user
profiling commands in an IB") is absent.

Next (smuggler build):
1. Track rb0 `_wptr` across our own submissions + GET insertions (deterministic
   sizedwords from addcmds; system rb0 traffic adds noise — mitigate by
   fast repeated cycles + WAIT_REG_MEM confirmation of our dword at candidate
   offsets).
2. Build the fake stream: choose countables (and RPTR entry point) so the
   interleaved fixed/controlled dwords decode to
   `CP_SET_PROTECTED_MODE 0` + `CP_INDIRECT_BUFFER_PFE -> attacker commands`
   (the whitepaper's alignment puzzle; usable dwords repeat every block).
3. Payload with PM off: program `CONTEXT_SWITCH_SAVE_ADDR` / SMMU TTBR0 →
   physical R/W (stage 4).

## STAGE 3c — whitepaper chain fully mapped onto our kernel (2026-10-10)

Fetched Guang Gong's USENIX-2020 whitepaper
(`ref/tiyunzong-wp.pdf`); its pages 16–19 describe this exact attack. Mapped to
our shipped kernel:

1. **`adreno_ringbuffer_allocspace` RPTR desync** (whitepaper Listing 13) —
   identical code, RPTR control already live (stage 2a).
2. **The smuggle primitive**: user cmdbatch profiling
   (`adreno_ringbuffer.c:919-1020`). With `KGSL_CMDBATCH_PROFILING` (0x10) and
   an objlist entry flagged `KGSL_OBJLIST_PROFILE` (0x10), the driver calls

   ```c
   _get_alwayson_counter(adreno_dev, cmds,
        cmdbatch->profiling_buffer_gpuaddr + offsetof(..., gpu_ticks_submitted))
   → [CP_REG_TO_MEM hdr][ALWAYSON_COUNTER_LO regsel][addr_lo][addr_hi]
   ```

   i.e. **two consecutive, fully user-chosen dwords** (the 64-bit profiling
   buffer GPU address) are written into the RB — **twice per submission**
   (pre/post IB). Whitepaper: "GPU address is 8 bytes. It's enough to write a
   CP_NOP or CP_SET_PROTECTED_MODE instruction into it."
3. **Preemption**: `nopreempt=N` at runtime → preemption enabled; A506 features
   `ADRENO_PREEMPTION` (adreno-gpulist.h).
4. **Attack flow (whitepaper fig. 9-11)**:
   - victim context (low-priority RB3) executes an IB containing a
     `CP_WAIT_REG_MEM` on an attacker-controlled flag;
   - while stalled, attacker's high-priority rb0 context corrupts the RPTR
     (scratch+0) and issues two `IOCTL_KGSL_GPU_COMMAND`s whose profiling
     gpuaddrs are crafted as `CP_NOP` and `CP_SET_PROTECTED_MODE 0`;
     `allocspace` (fooled) overwrites the victim's pending RB instructions
     with those dwords;
   - attacker satisfies the wait → victim resumes from the original RPTR →
     unaligned execution hits the smuggled `CP_NOP` (skips ahead) then
     `CP_SET_PROTECTED_MODE` → PM off → the next driver-inserted
     `CP_INDIRECT_BUFFER_PFE` jumps to the attacker IB **with protected mode
     off** → rewrite TTBR0 (SMMU) → arbitrary physical R/W → kernel patch.
5. **S3.0/S3.1 note**: our simple "lowest-prio stall + rb0 release" test did
   not release the WAIT (both directions tried). The whitepaper's release is
   the *overwriting commands themselves* (their user IB writes the flag) —
   revisit with a wait that has a finite timeout / a flag written by the
   overwriting submission.

Next session:
1. Extend the harness: submit with `kgsl_gpu_command.flags = KGSL_CMDBATCH_PROFILING`
   and an objlist entry `{gpuaddr = crafted, size, flags = KGSL_OBJLIST_PROFILE}`;
   confirm the crafted 8 bytes appear in the RB (RPTR/WAIT probes at expected
   offsets).
2. Implement the whitepaper race with the correct release condition.
3. Then stage 4 (TTBR0 → phys R/W).

## STAGE 3d — DONE (live, 2026-10-10): user profiling path active

`tools/kgsl_profile_submit.c`:

```
[1] cmd=0x300000 out=0x301000 prof=0x302000
[2] GPU_COMMAND(profiling) ret=0
[3] command marker -> OK
[4] profiling buffer: wall_s=0x6ac80ede wall_ns=0x25d6ee3c
    ticks queued=0x9c87 submitted=0x9dbd retired=0x9de7
[5] USER PROFILING ACTIVE -> 8 user-controlled bytes were in the RB
```

- Submission with `flags = KGSL_CMDBATCH_PROFILING` (0x10) and objlist entry
  `{gpuaddr = user buffer VA, flags = KGSL_OBJLIST_MEMOBJ|KGSL_OBJLIST_PROFILE}`
  succeeds; the kernel executes `_get_alwayson_counter` with
  `cmdbatch->profiling_buffer_gpuaddr` — our user buffer was used and had its
  tick fields filled by the GPU.
- Therefore the driver wrote **two consecutive user-chosen dwords**
  (`addr_lo`, `addr_hi`) of the profiling buffer address into the ringbuffer
  (twice per submission: pre/post IB) via the pre-fix, non-IB path.
- This is exactly the whitepaper's smuggling primitive, live on ABL766.

### Primitive set — all live

| # | primitive | status |
|---|---|---|
| 1 | arbitrary GPU command execution (shell) | notes/56 stage 0 |
| 2 | scratch @0xf8009000 + RPTR control (rb0) | notes/56 stages 1/2a |
| 3a | perfcounter GET injects 1 arbitrary dword into rb0 | notes/57 stage 3b |
| 3b | cmdbatch profiling injects 8 arbitrary dwords (2×) | notes/57 stage 3d |
| 4 | dmesg monitoring from shell | notes/57 |

Remaining: whitepaper race orchestration (victim wait + rb0 RPTR desync +
overwrite with crafted profiling gpuaddrs encoding CP_NOP /
CP_SET_PROTECTED_MODE) and stage 4 (PM-off TTBR0 → physical R/W).

## STAGE 3e — preemption timing validated (S3.2b, live)

`tools/kgsl_preempt_test.c`:

- victim ctx priority 12 → rb3: IB of 200,000 `CP_MEM_WRITE`s
  (OUT[1..200000] = i);
- preemptor ctx priority 1 → rb0: tiny marker IB (OUT[0] = 0xB0B0);
- preemptor submitted immediately after the victim; poll OUT[0], on hit sample
  OUT[5000] with a single-line invalidate.

```
[3] victim submit ret=0 preemptor submit ret=0
[4] preemptor marker seen=1  mid-sample OUT[5000]=0x1388   (== 5000)
[5] victim last=0x30d40                                    (== 200000)
```

- The rb0 batch executed while the rb3 victim had completed only ~5000 of
  200000 writes (≈2.5%): **cross-ringbuffer interleaving mid-IB confirmed**.
- (S3.0/S3.1 showed `CP_WAIT_REG_MEM` stalls are not released this way; use a
  long IB as the victim window instead of a wait.)

## STAGE 3f — overwrite orchestrator built; decisive negative (2026-10-10)

`tools/kgsl_overwrite_test.c` (control + `-DFULL`):

- Full choreography implemented: f1/f2/f3/f4 fillers to normalise rb3 `_wptr`
  (wrap ×2 + 150 spacer), victim = long 200k-write IB + 300-entry padding +
  marker last (outside CP prefetch), rb0 preemptor writes `scratch+12` (rb3
  RPTR slot) and a marker, attacker = 360-entry cmdbatch aimed at the wrap
  path with a distinct `OUT[9]=0xAA` slice.
- CONTROL run: clean (`OUT[9]=0xV1` present, structure intact, device alive).
- FULL runs (fake RPTR 7900, 8100, then decisive probe 0x1FFF):
  - preemptor executed mid-IB ✓ (validated again);
  - attacker submission **ret=0 with fake RPTR=0x1FFF** — if `allocspace(rb3)`
    had read the fake (8191 > `_wptr`), the ~2200-dword request would have
    been **ENOSPC**; it succeeded instead.
  - ⇒ **`adreno_ringbuffer_allocspace` on this build did not consume the fake
    RPTR value.** Victim marker remained present; no overwrite.
- Also discovered: the kallsyms dump (`recon/kallsyms-abl766.txt`) has a
  **name drift in the adreno_ringbuffer/adreno_get_rptr cluster** — the code at
  the "adreno_get_rptr" address (0x5414ac) is a refcount helper. All earlier
  "fuzzy symbol" results stem from this; addresses are monotonic but names are
  off by some entries in this region.

### Interpretation + next step

Two possibilities for the live negative:
1. The shipped Dec-2018 build's `adreno_get_rptr` does **not** read the RPTR
   from `device->scratch` (pre-scratch-era code: RPTR from memstore/IRQ), in
   which case the CVE-2019-10567/2020-11179 runtime primitive is dead here even
   though the profiling-write and scratch-write machinery exist.
2. The attacker submission did not go to rb3 (ruled unlikely: same ctx as victim
   ran on rb3 per dmesg in earlier tests).

Next session (static, no device):
1. Re-anchor `adreno_get_rptr` / `adreno_ringbuffer_allocspace` **by code
   structure** (scan for the `0x1FFE`/`0x2000` constants of allocspace and for a
   call to `kgsl_sharedmem_readl`-shaped code), bypassing the kallsyms drift.
2. Confirm the RPTR source on this build:
   - if scratch → debug why the fake was ignored (e.g., rb id vs slot, or a
     cached rptr in the rb struct);
   - if not scratch → the RPTR-desync route is closed on ABL766; the remaining
     GMX route would be the profiling-write alone (needs a different
     misalignment mechanism).

## STAGE 3f conclusion (static anchor, 2026-10-10)

Structural anchor (constant scan for the wrap mask, bypassing the kallsyms
name drift):

- **Real `adreno_ringbuffer_allocspace` = `0xffffffc0005259a0`** — disassembly
  matches the C source exactly: `ldr w3,[rb+0x88]` (`_wptr`), rptr via
  `bl 0x540708`, `#0x1ffe` end check, `cmp dwords,rptr`, and the wrap path
  builds the CP_NOP header incl. the `0x9669` odd-parity table and returns
  hostptr (offset 0) with `_wptr = dwords`.
- **rptr getter (`0x540708`)**: walks a pointer/state chain
  (`[x+0xf10] → [..+0x38] → [..] → [..] → w[+0x24]`, plus a state check
  `w-0x12c ≤ 0x63`) — it does **not** look like a `kgsl_sharedmem_readl` of
  `device->scratch`. Combined with the decisive live probe (fake
  `scratch+12 = 0x1FFF` was not consumed; attacker submit still ret=0), the
  conclusion is:
  **on ABL766 the kernel's RPTR for `allocspace` is not sourced from the
  scratch page** (cached/IRQ/memstore-driven), so the CVE-2019-10567 /
  CVE-2020-11179 *desync* step is not reachable on this build.

Status of the chain on ABL766:
- live, proven: GPU cmd exec, scratch addr, profiling 8-dword RB write,
  perfcounter 1-dword RB write, cross-RB interleaving, control overwrite
  choreography.
- blocked: the allocspace RPTR desync (kernel ignores the scratch shadow), so
  the RB overwrite cannot be steered at pending instructions.
- Remaining ideas: (a) find another kernel consumer of the scratch RPTR that
  *is* authoritative (e.g., timestamp/retire path), (b) exploit the
  profiling-write primitive through a different misalignment mechanism, or
  (c) fall back to the other kernel lanes (KGSL IOMMU primitive from
  notes/24-32 remains DoS-bounded; vold/SD parsers; etc.).



## add_profiling_buffer decoded (2026-10-10): arbitrary 64-bit RB value

`kgsl_cmdbatch.c:531-572`:

```c
if (id != 0) entry = kgsl_sharedmem_find_id(proc, id);
else         entry = kgsl_sharedmem_find(proc, gpuaddr);
if (entry && !kgsl_gpuaddr_in_memdesc(&entry->memdesc, gpuaddr, size))
        entry = NULL;
...
if (id != 0)
        cmdbatch->profiling_buffer_gpuaddr = entry->memdesc.gpuaddr + offset;
else
        cmdbatch->profiling_buffer_gpuaddr = gpuaddr;
```

- With `id != 0` and `obj.gpuaddr` = a valid address inside that entry,
  validation passes; the value used for the RB write is
  **`entry_base + offset` with `offset` a fully user-controlled 64-bit field**
  → the 8 RB bytes can be **any 64-bit constant**.
- With `id == 0` the value is verbatim `obj.gpuaddr` (must be in a mapping).
- Remaining subtlety: the REG_TO_MEM op that carries those 8 bytes also
  *executes* (writing the alwayson counter to that address) — if the crafted
  value is not itself a mapped GPU address, that write faults. Two ways out:
  (a) choose crafted values that are also mapped addresses (cpu-map VA
  `0x700000000+off` → bytes `[off][0x7]`, or driver-assigned VA < 4 GiB →
  bytes `[va][0]`), or (b) arrange the carrying op to be overwritten/skipped
  before the GPU executes it (the overwrite race itself) — resolve when
  building the orchestrator.
- Practical upshot: the smuggled `CP_NOP` (consumes arbitrary payload) is
  easy with either form; `CP_SET_PROTECTED_MODE 0` (needs payload 0) fits the
  `[va][0]` driver-assigned form (hi dword 0) or `[off][0x7]` chains that
  skip the 0x7 via a preceding controlled `CP_NOP` count.






