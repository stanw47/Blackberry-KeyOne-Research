# notes/50 — Pre-fix boot-image parser (AAN355) — downgrade-lane groundwork

Date: 2026-10-09
Related: notes/45 (fix list), notes/46 (fix diffs + reachability), notes/49
(write channel + token crypto). Evidence: `recon/fixdiff-aan355-bootparse.txt`.

## What was done

Instruction-level diff of the boot-image parse/load path:

- AAN355 (2017-08, vulnerable era): `boot_linux_from_flash`-class fn @
  `0x8f62b914` (972 B, 243 insns)
- ABL766 (2018-07, fixed): @ `0x8f62bb94` (1012 B, 243 insns)
- Tool: `tools/lk_func_diff.py <aan355.mbn> 0x8f62b914 <abl766.mbn> 0x8f62bb94 --len 972`

## Diff summary (what 2018 added)

- **Entry guards**: ABL766 adds early `movw/movt + cmp + bhi` bound checks before
  the parse begins (two compares against upper bounds).
- **Per-stage integer-overflow guards**: `movw/movt + cmp + bhi` inserted around
  each field consumption (image header fields), plus the new strings
  `ERROR: Integer overflow in boot image header %s` /
  `Integer overflow detected in bootimage header fields %u %s`.
- One check was **moved** (`ERROR: Invalid Device Tree size` now sits after the
  DT table validation; `Cannot read boot image` reordered) — the 2017 build can
  consume fields before the corresponding guard.
- The AAN355 code still contains the address-space overlap checks against
  `0x8f5f0000`/`0x8f600000`/`0x8fcfffff` (aboot/DDR ranges) and the
  Kernel/ramdisk "addresses overlap with aboot" guard — so the exploitable class
  is the **arithmetic wraparound in size/offset fields**, not a simple overlap.

## Candidate exploitation model (to validate offline)

AAN355 page-aligns `size + offset` with `add`/`bic` and compares against the
image buffer bounds without the wraparound guards added in 2018. If a crafted
Android boot header (`kernel_size`/`ramdisk_size` + `page_size` at 0x08/0x10/0x24)
wraps the computed end below the buffer size, the loader performs an
out-of-bounds read/copy into the load address space. Next step is reconstructing
the exact register flow from the AAN355 disasm (need the full function, not just
the diff window) and validating the wrap precondition on paper before any
device test.

## Device-side plan (when resumed; no action yet)

1. Current state: device healthy, Android booted after ABL766 flashall (adb off —
   fresh userdata; re-enable USB debugging for shell work).
2. Recovery net before downgrade:
   - backup bootchain `AAK171` reachable via POWER+VOL_UP (notes/42/43) — confirm
     its fastboot can flash the primary partitions (test a no-op stock `flash tz`
     there first).
   - primary `flash` channel is open pre-auth for boot-chain class (notes/49).
3. Minimal downgrade probe: flash **AAN355 `emmc_appsboot.mbn` only** (keep sbl1
   ABL766) → reboot → check `oem info` bootchain version / that fastboot still
   comes up. Rationale: aboot is the only image we need old; avoids touching
   sbl1/BBSS rollback surfaces. If SBL1 refuses the older aboot (no boot), recover
   via backup bootchain flash of the stock ABL766 aboot.
4. Only after the old aboot boots: flash the crafted `boot` image and iterate.
5. Never flash `sbl1` from an old package unless required; keep ABL766 package
   available at all times for one-command restore (`flashall.bat`).
