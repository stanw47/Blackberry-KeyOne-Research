# notes/81 — Backup-chain install is refused TWICE on permanent-WP; only raw writes (EDL) remain

Date: 2026-10-16. Follow-up to notes/80 (insecure backup bootchain found on-device).

## Question asked
Can we boot entirely from the backup chain / insecure chain without the root+staging work?

## Answer: no — both install paths are hard-refused on this unit

1. **Booting the existing backup chain** (POWER+VOL_UP) = AAK171, identical authboot
   gates (notes/43, live-tested). No gain.
2. **Android updater** (`bkup_bc_update`, extracted from AAN355 system image via debugfs):
   - `strings`: `ro.boot.binfo.bbss_wp_type` → **"Backup bootchain is permanent write
     protected"**.
   - Disasm (AArch64, capstone): at 0x1094-0x10a8 the "permanent" branch loads the
     string, logs, sets `w21=0`, exits (0x10ec→0x1138). No update performed.
   - Selection: `bbss_insecure` → insecure pkg; `bbss_wp_type` → wp-power_on_secure pkg.
     Version strings: "already up to date" / "will be updated". Manual modes
     `update-bootchain`, `update-backup-bootchain`, `update-pri-backup-bootchain`.
   - Passport's copy has the identical logic — works there only because the prototype
     is `wp=power_on`.
3. **Bootloader (`write_phyboot` @ ABL766 0x8f633bb8, inside `_emmc_recovery_init`)** —
   the BCB handler that flashes the staged pkg into the hidden **phyboot** partition:
   - `bsi_get_data` → `strcmp(data, "permanent")` → **"Can't update perm WP device!"**
     (0x8f6dbfb8) → returns error (0x8f633c24-0x8f633c3c).
   - Second refusal: **"Security of image doesn't match security of bootchain"**
     (0x8f6dc028 @ 0x8f633ef4) — the test-signed insecure images are refused on a
     secure bootchain.
   - Also: "Invalid partition"/"Invalid image"/"GPT header not found"/
     "Unable to find BBSS partition" (0x8f6dc15c) — it needs the hidden bbss partition.

⇒ **Double chicken-and-egg**: the insecure chain can only be installed on a device that
is already insecure and not permanent-WP. Root+staging does NOT help — aboot itself
refuses. The pkg is designed for factory (already-insecure) devices.

## What this leaves

| Route | Bypasses | Needs | Panic risk |
|---|---|---|---|
| **EDL + firehose** | everything (authboot, WP, aboot checks) | test-point entry + `prog_emmc_firehose_8953_ddr.mbn` (already have, from ABL766 autoloader) | none (no OS running) |
| Root → vtnvfs raw write of bbss/phyboot | aboot BCB checks (bypasses write_phyboot) | root (KGSL lane) + vtnvfs driver must not enforce WP (unknown) | high (KGSL) |
| Root → TZ/RPMB bootmode write | authboot | root + TZ service access | high (KGSL) |

EDL writes to perform (raw, no signatures involved):
- `phyboot` partition ← insecure chain (devcfgr/tzr/rpmr/abootr from AAJ281 pkg), and
- `bbss` partition ← `bbss_insecure=true` + insecure CA sets (`BB Root CA (insecure)` /
  `BB Attestation CA (insecure)` are embedded in the pkg).
Then POWER+VOL_UP boots the insecure chain; its SBL sets the tag
(`bsi_update bbss_insecure`) and ABL766's `initialize_rpmb_record_handler`
(0x8f671ce0) provisions the **test RPMB key** → bootmode writable → factory.

## Kernel-panic mitigation (user's warning)

- The KGSL lane panics often; the Passport precedent (session27): iovyroot's
  kernel→user return panics (grsec/KERNEXEC); the **kernel-only** fix = patch unused
  syscall-table slots (17/35 → prepare_kernel_cred/commit_creds) — no kernel→user
  control flow.
- Make the persistent write the **last action** (write → reboot); a panic after the
  write does not undo it.
- Note: for THIS goal root only matters for the vtnvfs/RPMB routes — the BCB/backup
  path is refused regardless.

## Artifacts
- `bkup_bc_update` (KeyOne AAN355): `/tmp/opencode/aan355/bkup_bc_update` (AArch64,
  14,432 B, stripped). Passport copy: `Blackberry-Passport-Research/.../system_tree/bin/`.
- ABL766 anchors: `write_phyboot` 0x8f633bb8; "Can't update perm WP device!" 0x8f6dbfb8;
  "Security of image..." 0x8f6dc028; BCB handler `_emmc_recovery_init` 0x8f630414;
  "Updating backup bootchain (%d B)" 0x8f63097c; "bootchain update succeeded, rebooting..."
  0x8f63082c.
