# notes/37 — KEYone anti-rollback, downgrade risk, and boot-chain provenance

Date: 2026-10-08

Question addressed: *Is the community/AI warning true that flashing an older
autoloader (e.g., AAK831) will "permanently hard-brick" a KEYone due to
Qualcomm anti-rollback?*

## Verdict

**Partly true, mostly overstated.**

- Anti-rollback (ARB) is real in the KEYone boot chain and is enforced at boot
  when the stored rollback version is **greater** than the incoming image's:
  - SBL1 carries `boot_rollback_version.c` and a refusal message
    `%s:vtnvfs:%s:%s(%d):version %d is not longer supported%s` — it reads
    version state from the QNX `vtnvfs` token store.
  - aboot's image-authentication path contains
    `BBSS anti-rollback greater than image`, alongside certificate parsing
    (`Unable to find SW_ID in certifiate`, `Unable to find HW_ID in
    certificate`, `SW_ID from BSI: %s`, `SW_ID from image: %d`,
    `MSM_ID doesn't match. Image is incompatible.`). It can also
    `Failed to update sbl anti-rollback fuse.` (write path via SCM).
  - TZ gained `/secboot/anti_rollback` handling during the 2017→2018 refresh.
- Failure mode if refused = the device does not boot the older chain. That is a
  **soft brick**, not a fused-forever brick: PBL/EDL still run, and recovery is
  EDL-flashing a signed image whose rollback version is >= the stored one.
  "Permanently hard-bricked" is wrong unless EDL is unreachable.
- `Anti-rollback protection disabled due to token presence` exists in aboot —
  the ARB path is token-gated/defeatable in factory/service flows.
- Community evidence: KEYone downgrades across major versions (8.1 ABP244 →
  7.1.1 AAX862) succeeded; there are no documented hard-brick cases from signed
  autoloader downgrades. The autoloaders are official service packages.

## Boot-chain provenance (evidence)

| image | AAL093 | AAN355 | ABL766 |
|---|---|---|---|
| aboot | 2514b7b79b / 1,925,631 | 4ff3615e80 / 1,949,815 | 14f90b3c1c / 1,952,062 |
| sbl1 | ebaa1a986a / 355,884 | 84e49f376a / 357,520 | b733cf958b / 357,520 |
| tz | 41776bb28c / 1,527,040 | 80b2e9a01b / 1,527,040 | c2d2ecac25 / 1,535,872 |
| rpm | ee6bf3d851 / 174,468 | 52d660c08d / 174,468 | b5d727bb00 / 174,468 |
| devcfg | 9dda3d7e18 / 39,236 | 438bf07f22 / 39,236 | 62459dc68b / 41,228 |

(sha256 prefix / size. No component is byte-identical AAN355 → ABL766: the
whole chain was rebuilt for the 2018 release.)

SBL1 build provenance (`QC_IMAGE_VERSION_STRING` / `OEM_IMAGE_VERSION_STRING`):

- AAL093: `BOOT.BF.3.3-00211` / `AAL093`
- AAN355: `BOOT.BF.3.3-00214` / `AAN355`
- ABL766: `BOOT.BF.3.3-00214` / `ABL766`

So SBL1 was rebased 00211→00214 (May→Aug 2017) and rebuilt again for ABL766
(same base, new OEM tag). Rollback-version bumps would land in SBL1/TZ.

## Where the checks live (ABL766)

- Image authentication / BBSS check: function @ `0x8f633c..`; ARB refusal string
  `0x8f6dc090` referenced @ `0x8f633f90`.
- ARB token bypass: `Anti-rollback protection disabled due to token presence`
  (`0x8f6dd698`) checked in fn around `0x8f6370f8` after `bl 0x8f63ca34`.
- BBSS rollback counters log (five values: BBSS, SBL, LK, SBLR, LKR):
  `0x8f654678`; struct fields at offsets 0x0/0x40/0x80/0xc0/0x100 of the BBSS
  record.
- `sbl_anti_rollback_ver`, `"  Anti-rollback: "` and
  `Failed to update sbl anti-rollback fuse.` in aboot since AAL093 — this
  machinery is not new.

## Practical guidance for the AAK experiment

1. **Never flash to answer the question.** Download AAK399/AAK879 and inspect
   `emmc_appsboot.mbn` first (`lk_xref.py` for the deny string; `lk_disasm.py`
   for the branch). Flashing is only on the table if the binary actually allows
   unlock.
2. If a flash is ever considered:
   - Have the current ABL766 autoloader staged.
   - Confirm EDL reachability (`adb reboot edl` / `fastboot oem` path) and the
     signed firehose programmer (we have it extracted).
   - Our unit is a BBB100-3 Sprint on the 7.1.1 line (never took Oreo), so its
     stored rollback state is likely minimal — but this cannot be confirmed
     without root/EDL reads.
3. The AI warning's operational conclusion ("only flash older images if the
   device is already bricked on a matching version") is over-cautious but not
   unreasonable for a *normal user*; for research we treat it as a
   recoverability-planning item, not a showstopper.

## Availability of AAK

- Confirmed mirror: HalabTech — `bbry_qc8953_autoloader_user-common-AAK399`
  (2.19 GB) and `AAK879` (2.19 GB).
- Not found on AndroidFileHost (Jcrutchvt10 set starts at AAN355), archive.org,
  or general web search. Exact-name searches on repair forums/Mega mirrors are
  the remaining route.

## Open next steps

- Locate ADR/PC-relative refs for SBL1 rollback strings (compiler used
  PC-relative addressing; no movw/movt or literal dword refs found) and
  disassemble the SBL1 version check.
- Optionally emulate the aboot ARB check with Unicorn to confirm refusal
  conditions.
