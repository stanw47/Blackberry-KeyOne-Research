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

## Device state

Wedged in fastboot again; physical reset required (hold Power ~15 s).
