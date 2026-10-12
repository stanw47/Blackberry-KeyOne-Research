# notes/65 — "Insecure board" factory tooling: what it is and what to hunt for the KEYone

Date: 2026-10-12 (evening). Related: notes/38 (BIDE/ECC delta), 40/41 (bbss),
64 (bbss corner verdict).

## 1. Reading `bbss_insecure` — the answer

**`fastboot oem info`** — the `Insecure: false/true` line IS the parsed
`bbss_insecure` tag (aboot parses the bbss store at boot and prints it; command
allowed pre-auth). We have been reading it live all along. The raw bbss
partition itself is NOT addressable by name (`oem parthash:bbss` ->
"Partition doesn't exist"; hidden LUN); only EDL/off-chip access reads it.

## 2. New community artifacts (Ventoy + Downloads)

- `SQN100-2.Q10.MFI_Insecure_4.0.11.435.exe.zip` and
  `STO100-1.Z50.MFI_Insecure_4.1.2.272.exe.zip` — **BB10 "MFI/Insecure board"
  factory autoloaders** (Q10, Z50). Proof that BlackBerry shipped
  factory-flashable *insecure* packages for device families.
- `BR-classicna-Insecure.sfi` + `.signed.sfi` and
  `BR-windermereemea-Insecure.sfi` + `.signed.sfi` — Insecure vs Signed pairs
  (~180-210k differing bytes; they are *different builds*, not re-signs).
- `rimboot_update-qct` (QNX-ARM 19 KB) — device-side factory updater:
  GPT validation + **eMMC boot-sector writes** (`get_bootrom_offset`,
  `boot_sector_write_protected`, `SBL2BootROM`) + reboot. This is the
  mechanism class used to (re)program boot0/boot1 from a running OS.
- `BlackBerry HWID Table.xlsx` — full HWID/model/codename/variant table for
  BBOS/BB10/Android-era devices (useful for imggen targets + identity work).
- `~/priv-research` + recon: `bkup_bc_update` (KEYone Android-side binary that
  updates the backup bootchain), `libgetboardinfo`, etc.

## 3. What this means for the KEYone

The "insecure board" factory concept is real and repeatable across BB
products. **The KEYone-relevant prize would be an equivalent factory/MFI or
insecure autoloader for `qc8953` / `bbb100`** (naming variants to hunt:
`bbry_qc8953_autoloader_*mfi*`, `*factory*`, `*insecure*`, `*testv*`).
If such a package exists it would either (a) flash factory-signed images
accepted in the insecure state, or (b) provision the insecure state itself
(RTAS/factory-authorized). Both equal "boot another OS".

### Hunt list (community mirrors / the group the Q10/Z50 files came from)
1. `bbry_qc8953` autoloader variants beyond user-common/user-alldevices/TESTV3.
2. Any BBB100 "MFI"/"factory"/"insecure"/"bringup" package.
3. The Q10/Z50 MFI_Insecure packages' *scripts/config* (what do they change
   vs the user-common builds? -> webarchive: dive when time permits).

## 4. Constraints reaffirmed

- No shop / no opening the device / no chip-off (perfect condition, and the
  chip route is "not a win" for research). Software and non-invasive only.
- `bbss_insecure` remains a **one-write-wins** objective (plaintext tag), but
  every pre-auth path is closed (notes/64).
- /tmp is tmpfs — never extract large files there (RAM exhaustion).
