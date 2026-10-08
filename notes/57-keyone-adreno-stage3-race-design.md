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
