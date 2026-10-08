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


