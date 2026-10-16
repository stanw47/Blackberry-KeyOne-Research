# notes/80 — The on-device insecure backup bootchain: KeyOne's own unlock package (4-task results)

Date: 2026-10-16. Tasks: (1) eng-aboot hunt, (4) MSM8953 TZ CVE mining, (3) live-device
backup_bootchain check, (2) PKI comparison vs Passport prototype.

## 1. Eng-aboot hunt — no public dump, but the mechanism is confirmed

- XDA (SKDushow TWRP thread): KEYone **engineering units with unlocked bootloaders
  exist** (video proof); owners need "factory engineering phone". Community:
  "The KeyOne was unlockable before it got a patch" — note 38 already refuted
  this for all 4 public retail builds (AAK399/AAL093/AAN355/ABL766 all deny).
- `qualcomm_avb_exploit_poc` (atlas4381, 2026): edk2 ABL AVB path — **not applicable**
  (KEYone = LK, no vbmeta; our layout has `bootsig` classic sig records).
- `lowendmains/edlunlock` (devinfo hex-pattern): **not applicable** — notes/61:
  devinfo `is_unlocked` is already 1 and `verify_hlos_image` never reads devinfo.
- Leads for the real thing: **DiabloSat** (github progzone122, Telegram @DiabloSat,
  Discord, about.diablosat.cc) — wall-of-shame credits them for "engineering models"
  info; SKDushow's eng unit (XDA); Chinese marketplaces (工程机 units).
- The engineering-aboot route remains the Passport/Priv precedent (F1) — but see §4:
  we may not need it.

## 2. MSM8953 TZ CVE cluster (device patch level 2018-12-05)

- cvefeed: MSM8953 firmware = **332 CVEs, 45 with public PoCs, 4 CISA KEV**.
- TZ/QTEE published after 2018-12 (likely unpatched on-device): CVE-2018-13910
  (TZ OOB, SD625 affected, 2019-06), CVE-2019-2274 (TZ access control, 2019-12),
  CVE-2019-14009 (TZ app pointer offset), CVE-2019-14116 (TZ XPU debug policy),
  CVE-2019-13994/13995 (TZ integer overflow IPC), CVE-2019-10562/10589 (QTEE),
  CVE-2019-10574 (Keymaster trustlet — Check Point).
- Check Point's trustlet-load chain (CVE-2015-6639 + CVE-2016-2431) exploited the
  same QSEE generation (Moto G4, SD617). No public MSM8953 TZ PoC; requires new
  exploit work after kernel root (KGSL lane).

## 3. LIVE DEVICE: `/system/vendor/backup_bootchain/` contains BOTH pkgs

```
/system/vendor/backup_bootchain/
  backup_bootchain_insecure.pkg.gz          1,745,844 (2018-11-21)
  backup_bootchain_wp-power_on_secure.pkg.gz 1,744,991 (2018-11-21)
```
- Same mechanism as the Passport prototype (session22/27): `bkup_bc_update` stages
  a pkg into `bcota` + BCB, bootloader flashes it as the **backup boot chain**;
  POWER+VOL_UP boots it (device currently boots backup BC **AAK171**).
- Files are root-only (shell can't read); but the **AAN355 system image carries
  the same pair** (extracted via debugfs from `bb-wine/keyone/aan355/img/system.img`
  after sparse→raw conversion). Preserved in
  `recon/2026-10-16/insecure-backup-bootchain/pkg/`.
- pkg container: magic `ce7e9d77`, BC-version string `AAJ281` @0x10; payload GPT =
  {devcfgr, tzr, rpmr, abootr}. **abootr = AAC603** (1,919,488 B; code @ file 0x8000,
  base 0x8f600000, same LK convention as ABL766).

## 4. PKI comparison (the bombshell)

| Image | Signer certs found |
|---|---|
| KEYone **insecure** pkg | **`CN=SecTools Test User, O=SecTools` (Qualcomm TEST cert)** — SW_ID 0x5/0x7/0xA, DEBUG=2 — plus BlackBerry SW_ID 0xC DEBUG=2 |
| KEYone abootr (AAC603) | BlackBerry SW_ID 0xC, HW_ID 0x460E1, DEBUG=2 |
| KEYone ABL766 (retail) | BlackBerry SW_ID 0xC, APP_ID 0x1000/0x1001/0x1007 |
| Passport insecure pkg | BlackBerry leaf `CN=Bryon Hummel` (production-PKI attestation), SW_ID 0x0/0xC |

⇒ The KEYone's insecure backup chain is **Qualcomm-test-signed** (the widely-leaked
SecTools test keys), while the retail chain is BlackBerry production-signed. The
insecure pkg also embeds `BB Root CA (insecure)` / `BB Attestation CA (insecure)` —
the insecure trust anchors the updater writes into the hidden `bbss` partition
(`bsi_update bbss_insecure`, `bbss_insecure`, `bbry_is_insecure: TRUE`,
`insecure device; ignoring SBL auth failure!`, `Insecure build, ignoring version`).

Retail ABL766 corroborates (§4b): `initialize_rpmb_record_handler` @ 0x8f671c60 →
`bbry_is_insecure` @ 0x8f654f48 → **`provision_rpmb_test_key`** @ 0x8f672518
(0x8f671ce0-0x8f671cec). Insecure state ⇒ RPMB uses the **test key** ⇒ bootmode
record writable without RIM's key.

## 5. The KeyOne factory-mode plan (Passport-prototype plan verbatim)

1. **Kernel root** (KGSL lane, notes/58/76 — active).
2. Stage `backup_bootchain_insecure.pkg` (AAJ281) via `bkup_bc_update`/bcota+BCB
   (root; version AAJ281 > installed AAK171 ⇒ "forcing auto-upgrade" path).
3. Reboot with backup key combo → insecure chain (test-signed tz/rpm/devcfg +
   AAC603 aboot) → sets `bbss_insecure` → `bbry_is_insecure: TRUE`.
4. RPMB test-key provisioned → `oem set-factory-mode` / direct bootmode write /
   flash unsigned images (KEY2-equivalent end state, software-only).

Open questions: (a) whether AAC603's `authboot_check_permission` short-circuits on
insecure (its `movw/movt` string xrefs are unresolved — layout differs from ABL766;
needs a corrected segment map); (b) whether the `bbss` CA-set write is blocked by
`bbss_wp_type=permanent` (KeyOne bbss is a hidden user-area GPT partition, not
boot0 — notes/41); (c) the primary SBL1's acceptance of the test-signed tzr/rpmr
when the backup key combo is held.

## 6. Artifacts

- `recon/2026-10-16/insecure-backup-bootchain/` — pkgs (.gz + unpacked), GPT-extracted
  `parts/{devcfgr,tzr,rpmr,abootr}.img`, extracted X.509 DERs (fingerprints above).
- Live device probes (read-only): binfo props (bbss_insecure=false, wp=permanent,
  backup_bc AAK171, bsis_lite, oem_tag sprint), /system/vendor/backup_bootchain
  listing.
