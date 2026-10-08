# notes/41 — BBSS storage resolved; EDL gate tested (results)

Date: 2026-10-08
Follow-up to notes/39/40. Items #1 and #2 of the planned experiments.

## #1 — What backs the BBSS/BSI record table

**A hidden GPT partition named `bbss` (UTF-16), absent from public GPTs.**

- In ABL766, the record search copies a 10-byte literal (UTF-16 `"bbss"`) and
  scans GPT entries comparing 10 bytes (`0x8f633c40`–`0x8f633d90`); failure
  prints `"Unable to find BBSS partition"`.
- The public service GPT (`gpt_main0.bin`, also `gpt_backup0.bin`,
  `gpt_both0.bin`) contains **56 partitions and no `bbss`** (nor `phyboot`,
  another hidden name checked at `0x8f633bd4`).
- Consequence: `bbss` (and `phyboot`) are **factory-created hidden partitions**
  not present in the service packages. The BSI tags
  (`bbss_insecure`, `bbss_wp_type`, `bsis_type`, `bbss_antirollback`, …) are
  read/written there, via the vtnvfs driver
  (`vtnvfs_read_drv/write_drv/format_drv`; `oem format <partition>` path).
- `oem info` on retail reads these values live — so the partition exists on the
  device even though the service GPT we hold does not describe it.

Implications:
- The data route (`flip bbss_insecure`) needs write access to a hidden
  partition: **EDL (hardware-gated) or root**, not fastboot.
- The live GPT (with hidden entries) can only be dumped via EDL/`oem gptinfo`
  (RTAS-gated).

## #2 — EDL reachability (software)

Tested on the live BBB100-3 (adb serial 1164118297):

- `adb reboot edl` → device simply rebooted to Android. No `05C6:9008`.
- aboot contains only **checks** for dload mode:
  `SCM call to check dload mode failed: %x`, `dload mode not entered`
  (dword-referenced at `0x1b316c`); no command to *enter* dload.
- Bootloader menu string `3 - Reboot into fastboot.` — the on-device menu
  offers fastboot, not EDL. Boot modes are RPMB-backed
  (`Failed to read back bootmode from rpmb`, `Changed boot mode to %s`).

**Conclusion: EDL is not reachable in software on this unit** — test
points/hardware entry remain required, consistent with the community record.

## Loaders inventory (bkerler/Loaders)

- `009720e100000000_93f5fd0e3a74b5b5_fhprg_peek.bin` (320,060 B, **ELF32**):
  BlackBerry-signed (subject `BlackBerry`, `BBOS-Bootloader@blackberry.com`),
  strings list `MSM8952 / MSM8953 / …` → **our 8953 peek programmer**.
  Downloaded to `%TEMP%\opencode\edl\`.
- `009470e100000000_1e36d5637772a25e_fhprg.bin` (459,752 B, **ELF64**):
  supports `MSM8996 / MSM8998 / …` — **not** KEYone-compatible.

## Tools status

- `bkerler/edl` cloned (`%TEMP%\opencode\bkerler-edl`), deps installed
  (`pycryptodomex` included; module import verified).
- Task #3 (pre-auth fastboot probes / AAK→AAL code diff) is next; the BIDE
  messages appear not to be referenced by absolute pointers, so a structural
  function-level diff is needed rather than a string-xref shortcut.
