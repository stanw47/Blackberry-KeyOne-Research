# notes/47 — Long `getvar` names wedge the bootloader (DoS-class candidate)

Date: 2026-10-08
First pre-auth probe batch against ABL766 (live BBB100-3).

## Observations

Method: `fastboot getvar <name>` / `oem` variants, liveness check between probes.

| Probe | Result |
|---|---|
| `getvar` + 200-char name | responded (echo + Finished), device alive |
| `getvar` + 1000-char name | response started (echo visible); next probe's liveness ok? (ambiguity) |
| `getvar` + 4000-char name | response started (echo visible) |
| `getvar %s%s%s%s…` (format string) | **AdbWriteEndpointSync timeout (121)** |
| `getvar %n` | timeout |
| `getvar :.%08x.:%x` | timeout |
| `oem` (no arg) | host-side usage error |
| `oem` + 500-char arg | timeout |
| `oem info` + 300-char arg | timeout |
| `fastboot reboot` | FAILED timeout — device wedged |

**Conclusion: one of the long-name probes wedged the fastboot interface.** The
signature is identical to the `oem gptinfo` wedge (notes/42): the device still
enumerates (`fastboot devices` OK) but every command write times out; only a
physical reset recovers.

## Why this matters

- This is a **new, host-controlled, pre-auth input path** that reaches a state
  failure in the command handler — precisely the class where the KEY2-class
  fastboot bugs live (CVE-2021-1931: improper validation of buffer length
  while processing fastboot commands).
- Two possible mechanisms:
  1. **Stack/static overflow in the getvar-name handling** (crash → hang), or
  2. a logic hang (e.g., buffer/parse loop stuck after a length cutoff).
- The whole-line length check exists (`"Command line length is %d, maximum is
  %d"` @ `0x8f63b5e8` region) — so either the getvar *name* is copied into a
  smaller buffer before that check, or the check is bypassed by this path.

## Threshold plan (needs device; one probe per fresh boot)

1. Determine the exact threshold: test 256, 384, 512, 768, 1000 chars,
   one probe per boot (reset between), recording response vs wedge.
2. Inspect the command dispatcher + getvar handler statically around
   `0x8f63b5e8` (line-length check) and `cmd_getvar` (`0x8f62f6bc`) to find
   where the name is copied and what buffer holds it.
3. If a bounded copy into a fixed buffer is found, build a controlled pattern
   (e.g., long 'A' name) and observe crash behavior vs the known wedge —
   test whether control-flow corruption (e.g., device resets/takes longer)
   vs a pure hang.

## Threshold test result (live)

- `getvar` + 2049-char name (total command 2056 bytes) → **device wedged**
  (liveness probe + `fastboot reboot` both time out; physical reset needed).
- Combined with the earlier batch: 1007-byte command OK, 2056-byte command
  wedges → **boundary at/inside (1007, 2056]**, matching the 0x800 (2048)
  maximum command line from the length-check string.

## Command loop static analysis (`fastboot_command_loop`)

Disassembly (`0x8f62f138`+):

- `memalign(0x40, 0x1000)` → **4 KB command buffer** (heap).
- Per iteration: `memset(buf, 0, 0x40)`, receive via transport vtable
  `[r7+0x20]` (= `0x8f62eb0c`) with `r1 = 0x40`, NUL-terminate at the returned
  length, print `"fastboot: %s"`, then dispatch:
  - special-case `getvar:partition-type` (21-byte strncmp),
  - whitelist/permission route (`authboot_check_command_permission` call),
  - command table lookup, unknown → `FAIL`.
- So commands are processed in **64-byte chunks**; long commands span multiple
  reads and must be reassembled somewhere — or are truncated/desynced.
- The only explicit max is the `0x800` "Command line length" check
  (`0x8f63b5e8` region). Exceeding it does not produce a clean error — it
  wedges the transport (observed).

## Open questions

1. Where does the reassembly of multi-chunk commands happen, and is there a
   copy into a **smaller fixed buffer** before the 0x800 check?
2. Is the wedge a pure transport deadlock (DoS) or memory corruption?
   Distinguish by sending a command far beyond the limits (e.g., 8 KB) and
   watching behaviour: deadlock-reset vs corrupt-reset vs no-recovery.
3. Identify the exact length check applied to the fastboot input path
   (the `0x8f63b5e8` function may be a different module's logger).

## Device state

Wedged in fastboot again; physical reset required (hold Power ~15 s).

## Static follow-up (cmd_getvar + length check)

- `cmd_getvar` @ `0x8f62f6bc`: bounded throughout — copies variable
  values into a **0x40-byte stack buffer** via strlcpy/strlcat-style calls
  before sending. No unbounded copy on the name.
- Length check region (`0x8f63b5e0`): computes **max command line = 0x800
  (2048 bytes)** (`mov r2, #0x800; rsb r3, r1, r2`) and logs
  `"Command line length is %d, maximum is %d"`.
- Probe sequence fits an overflow hypothesis at the *receive/dispatch layer*:
  - 200-char name → OK
  - 1000-char name → response started (1007 total < 2048) → OK
  - **4000-char name → exceeded 0x800; subsequent commands all timeout**
  - Later probes (`%s…`, `%n`, colons, long `oem`) fail because the device
    was already dead — not because of their content.

## Revised hypothesis

The **fastboot command-receive buffer** (expected to be the 0x800 command
line) is overflowed/hung when the host sends more than the maximum *before*
the length check is enforced — consistent with the CVE-2018-5854 class
("stack-based buffer overflow in fastboot"). Next: locate the command loop
(`fastboot: processing commands` string) and its buffer size, and determine
check ordering (read-into-buffer vs length validation).

## Threshold test plan (one probe per boot, after reset)

1500 / 2048 / 2049 / 2500 / 3000-char `getvar` names; record response vs
wedge. If wedge starts just above 0x800, the max-length boundary is the
trigger and the input path must be inspected for pre-check writes.
