# notes/34 — KEYone eMMC write-protect: what aboot does with `bbss_wp_type`

Date: 2026-10-08. Device: BBB100-3 ABL766. Binary: `emmc_appsboot.mbn`
(MBN-wrapped raw ARM at file `0x8000` → VA `0x8f600000`). Method:
`tools/lk_xref.py` (movw/movt + literal-pool xref tracking) + capstone ARM.

## 1. Where the policy is read

`0x8f6547fc` parses the boot-info props:

| prop | value | stored |
|---|---|---|
| `bbss_wp_type` | `"permanent"` | mode flag = 0 |
| `bbss_wp_type` | `"power-on"` | mode flag = 1 |
| `bbss_wp_type` | `"none"` | mode flag = 2 |
| `bbss_insecure` | `"true"` | separate flag = 1 |

Globals live at `0x8f79488c+0x1c` (mode) and `+0x18` (insecure).
`oem info`'s "WP Type: permanent" is exactly this prop.

## 2. Boot gate — user builds only

Boot caller at `0x8f6009b8`:

```
bl 0x8f65528c        ; returns build-variant flag (0=user)
cmp r0, #0
bne 0x8f60085c       ; eng/userdebug -> SKIP write protection entirely
bl 0x8f655390        ; WP manager
...
bl 0x8f654f88        ; is_permanent(): 1 only when mode == 0
```

`0x8f65528c` just returns global `[0x8f7bebdc]`, which the variant checker
(`0x8f6552cc`, strings `"userdebug"`/`"eng"`) sets to 2/1. So WP is armed only
on production `user` builds.

## 3. What gets protected — GPT attribute bit 60

`WP_manager` (`0x8f655390`):
1. Sanity-checks that partition offsets are monotonically increasing
   ("Invalid partitions %llx(%d) <= %llx(%d)").
2. Iterates every partition; the selector is `0x8f607438` =
   `(partition_entry[0x44] >> 28)` — i.e. **GPT attribute bits 60-63**
   (attribute flag dword high nibble).
3. Coalesces runs of selected, contiguous partitions and applies each run:
   "Write protect group %d (%d partitions) : 0x%llx - 0x%llx" /
   "FAILED to apply write protect : group %d ...".

On the KEYone GPT every protected partition carries exactly
`attributes = 0x1000000000000000` (**bit 60**), and they form two runs:

- **Run 1 (LBA 40–498063):** prdid, boardid, sbl1, rpm, tz, devcfg, aboot,
  tunning, traceability, fsg, boot, bootsig, keymaster, lksecapp, cmnlib,
  cmnlib64, modem, ddrbak, dip, mdtp, devinfo, apdp, msadp, dpo, splash, ddr,
  sec, limits (28 partitions)
- **Run 2 (LBA 1048576–11534335):** oem, system

fsc…bbpersist, recovery, cache, userdata etc. have attr 0 and are never in a
WP group.

## 4. How it is applied — CMD28/29 user-area WP

Applier `0x8f60eb74` (called per group):
- refuses if the controller reports no user-WP support:
  "Err: User write protection feature not supported";
- requires `ERASE_GROUP_DEF` (writes EXT_CSD[0xAF]=1 if clear);
- needs the WPG size ("Err: Could not read WPG size") and demands block
  alignment ("Err: Memory not aligned to WPG blocks ...");
- issues **CMD28/29** range write-protect ("Address for CMD28/29 is out of
  range", "Length is less than min WP size, WP was not set"),
- polls card status ("Card status timed out after sending write protect
  command", "Failed to get card status afterapplying write protect").

Verification loop `0x8f60e300`: "Failed to Disable PERM WP",
"Failed to read ext csd for the card", "Power on protection is disabled,
cannot be set", "Failed to set power on WP for user". The `permanent` mode
takes an extra step: `is_permanent()` (`0x8f654f88`) is true only for mode 0,
and boot then calls `0x8f635900(0x35)` with Keymaster strings present
(`km_secure_write_protect`, `KEYMASTER_SECURE_WRITE_PROTECT`) — i.e. the
permanent variant is TZ/Keymaster-attested. Failure prints
"ERROR: FAILED to WP one or more partitions".

There is also a `backup_bootchain` prop read on this path (the same BBSS
backup-chain mechanic seen on the Passport).

## 5. Does the live KEYone actually have eMMC write protection? No.

If `permanent` mode had really armed user-area WP for the attr-60 run (which
includes `sbl1`, `aboot`, `boot`, `system`, `oem`, `devinfo`), those
partitions could never be written again — no OTA, no factory reflash, no
unbrick. Observed reality:

- the official autoloader rewrites boot/system/oem/sbl1/aboot routinely
  (`rawprogram0.xml`) and has recovered this unit multiple times;
- notes/09 recorded locked-fastboot `erase`/`flash` of `sbl1` and `aboot`
  succeeding.

So on retail units the permanent arm is not effective (controller/user-WP
capability, TZ gating, or a failing apply that is logged and skipped). At
most, a **temporary power-on WP** could be applied per boot (CMD28 WP is
cleared by power cycle/CMD29, and the flash path may clear it before writing).

## 6. Verdict

- **Functionally: the KEYone has no eMMC write protection on the unlock path.**
  The boot chain is in the user-area GPT, has no boot0/boot1, and every
  attr-60 partition is demonstrably rewritten by the factory tooling.
- The aboot machinery is real and policy-driven: a unit where the permanent
  path executes (supported WPG + Keymaster step) would have the attr-60
  partitions permanently WP'd, which would also make that unit un-updatable —
  i.e. not a shipped configuration.
- Absolute EXT_CSD confirmation (`BOOT_WP`, `BOOT_WP_STATUS`, `USER_WP`,
  WP-group bits) still requires root or the signed firehose programmer via
  EDL; it cannot be read from the running OS on this device.

## Files

- `tools/lk_xref.py` — string/address xref finder for `emmc_appsboot.mbn`.
- `firmware/keyone-abl766/.../gpt/gpt_main0.bin` — GPT with the attr-60 flags.
